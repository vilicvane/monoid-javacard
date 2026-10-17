package monoidsafeidentity;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacardx.crypto.Cipher;

/** AES-GCM with a 12-byte nonce, a 16-byte tag and empty associated data. */
public final class AESGcmCipher {

  private static final short BLOCK_LENGTH = 16;
  private static final short NONCE_LENGTH = 12;

  private final Cipher cipher;
  private final GHASH hash;
  private final byte[] counter;
  private final byte[] block;
  private final byte[] tag;
  private final byte[] operation;

  public AESGcmCipher() {
    // Identity is called through a Shareable while Safe or Monoid is selected.
    cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, true);
    hash = new GHASH();
    counter = JCSystem.makeTransientByteArray(BLOCK_LENGTH, JCSystem.CLEAR_ON_RESET);
    block = JCSystem.makeTransientByteArray(BLOCK_LENGTH, JCSystem.CLEAR_ON_RESET);
    tag = JCSystem.makeTransientByteArray(BLOCK_LENGTH, JCSystem.CLEAR_ON_RESET);
    operation = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
  }

  /** Initializes one operation with the fixed HPKE profile's 12-byte nonce. */
  public void init(AESKey key, byte mode, byte[] nonce, short nonceOffset) {
    operation[0] = mode;
    cipher.init(key, Cipher.MODE_ENCRYPT);

    Util.arrayFillNonAtomic(counter, (short) 0, BLOCK_LENGTH, (byte) 0);
    cipher.doFinal(counter, (short) 0, BLOCK_LENGTH, block, (short) 0);
    hash.init(block, (short) 0);

    // For a 96-bit nonce, J0 = nonce || 0x00000001.
    Util.arrayCopyNonAtomic(nonce, nonceOffset, counter, (short) 0, NONCE_LENGTH);
    counter[(short) (BLOCK_LENGTH - 1)] = 1;
    cipher.doFinal(counter, (short) 0, BLOCK_LENGTH, tag, (short) 0);
  }

  /**
   * Processes one complete message after init. Exact in-place operation is supported.
   * Decrypted output remains internal until CommunicationCipher verifies its tag.
   */
  public short doFinal(byte[] input, short offset, short length, byte[] out, short outOffset) {
    short remaining = length;

    while (remaining > 0) {
      short blockLength = remaining < BLOCK_LENGTH ? remaining : BLOCK_LENGTH;

      incrementCounter();
      cipher.doFinal(counter, (short) 0, BLOCK_LENGTH, block, (short) 0);

      // Authenticate ciphertext before exact in-place decryption overwrites it.
      if (operation[0] == Cipher.MODE_DECRYPT) {
        hash.update(input, offset, blockLength);
      }

      for (short index = 0; index < blockLength; index++) {
        out[(short) (outOffset + index)] = (byte) (input[(short) (offset + index)] ^ block[index]);
      }

      if (operation[0] == Cipher.MODE_ENCRYPT) {
        hash.update(out, outOffset, blockLength);
      }

      offset += blockLength;
      outOffset += blockLength;
      remaining -= blockLength;
    }

    // Empty AAD contributes a zero length; the message length is encoded in bits.
    Util.arrayFillNonAtomic(block, (short) 0, BLOCK_LENGTH, (byte) 0);
    block[13] = (byte) (length >> 13);
    block[14] = (byte) (length >> 5);
    block[15] = (byte) (length << 3);
    hash.update(block, (short) 0, BLOCK_LENGTH);
    hash.output(block, (short) 0);

    for (short index = 0; index < BLOCK_LENGTH; index++) {
      tag[index] ^= block[index];
    }

    return length;
  }

  /** Copies the complete 16-byte tag. */
  public short retrieveTag(byte[] out, short offset) {
    Util.arrayCopyNonAtomic(tag, (short) 0, out, offset, BLOCK_LENGTH);

    return BLOCK_LENGTH;
  }

  /** Reads every byte of the 16-byte tag and preserves the state. */
  public boolean verifyTag(byte[] input, short offset) {
    short difference = 0;

    for (short index = 0; index < BLOCK_LENGTH; index++) {
      difference |= tag[index] ^ input[(short) (offset + index)];
    }

    return difference == 0;
  }

  private void incrementCounter() {
    short carry = 1;

    for (short index = (short) (BLOCK_LENGTH - 1); index >= NONCE_LENGTH; index--) {
      short value = (short) ((counter[index] & 0xFF) + carry);

      counter[index] = (byte) value;
      carry = (short) (value >> 8);
    }
  }
}
