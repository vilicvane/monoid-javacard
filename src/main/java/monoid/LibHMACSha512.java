package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;

public final class LibHMACSha512 {

  private static final byte IPAD = (byte) 0x36;
  private static final byte OPAD = (byte) 0x5c;

  public static final short BLOCK_BYTES = (short) 128;
  private static final short OUT_BYTES = (short) 64;

  private static Signature sharedSignature;
  private static HMACKey sharedKey;
  private static MessageDigest sharedDigest;

  public static void init() {
    try {
      sharedSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_512, true);
      sharedKey = (HMACKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_HMAC_TRANSIENT_RESET,
        KeyBuilder.LENGTH_AES_256,
        false
      );
    } catch (Exception e) {
      sharedSignature = null;
      sharedKey = null;
      sharedDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, true);
    }
  }

  public static void dispose() {
    sharedSignature = null;
    sharedKey = null;
    sharedDigest = null;
  }

  public static short digest(
    byte[] key,
    short keyOffset,
    short keyLength,
    byte[] data,
    short dataOffset,
    short dataLength,
    byte[] out,
    short outOffset
  ) {
    byte[] block = sharedSignature == null || sharedKey == null
      ? JCSystem.makeTransientByteArray(BLOCK_BYTES, JCSystem.CLEAR_ON_RESET)
      : null;

    return digest(key, keyOffset, keyLength, data, dataOffset, dataLength, out, outOffset, block);
  }

  /** Reuses a separate BLOCK_BYTES workspace; key and data may overlap the output. */
  public static short digest(
    byte[] key,
    short keyOffset,
    short keyLength,
    byte[] data,
    short dataOffset,
    short dataLength,
    byte[] out,
    short outOffset,
    byte[] block
  ) {
    if (sharedSignature != null && sharedKey != null) {
      sharedKey.setKey(key, keyOffset, keyLength);
      sharedSignature.init(sharedKey, Signature.MODE_SIGN);

      return sharedSignature.sign(data, dataOffset, dataLength, out, outOffset);
    } else {
      try {
        sharedDigest.reset();
        Util.arrayFillNonAtomic(block, (short) 0, BLOCK_BYTES, IPAD);

        for (short keyIndex = 0; keyIndex < keyLength; keyIndex++) {
          block[keyIndex] ^= key[(short) (keyOffset + keyIndex)];
        }

        sharedDigest.update(block, (short) 0, BLOCK_BYTES);
        sharedDigest.doFinal(data, dataOffset, dataLength, out, outOffset);

        // The inner digest may have overwritten key. Convert the saved pad in place.
        for (short index = 0; index < BLOCK_BYTES; index++) {
          block[index] ^= (byte) (IPAD ^ OPAD);
        }

        sharedDigest.update(block, (short) 0, BLOCK_BYTES);

        return sharedDigest.doFinal(out, outOffset, OUT_BYTES, out, outOffset);
      } finally {
        sharedDigest.reset();
      }
    }
  }

  public static byte[] digest(byte[] key, byte[] data) {
    byte[] out = JCSystem.makeTransientByteArray(OUT_BYTES, JCSystem.CLEAR_ON_RESET);

    digest(
      key,
      (short) 0,
      (short) key.length,
      data,
      (short) 0,
      (short) data.length,
      out,
      (short) 0
    );

    return out;
  }
}
