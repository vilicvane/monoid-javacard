package monoid;

import javacard.framework.*;
import javacard.security.*;

public final class HmacSHA512 {
  private static final byte IPAD = (byte) 0x36;
  private static final byte OPAD = (byte) 0x5c;

  static final short BLOCK_SIZE = (short) 128;
  static final short OUT_SIZE = (short) 64;

  static Signature sharedSignature;
  static HMACKey sharedKey;
  static MessageDigest sha512;

  static short digest(byte[] key, short keyOffset, short keyLength, byte[] in, short inOffset, short inLength,
      byte[] out, short outOffset) {
    if (sharedSignature != null && sharedKey != null) {
      sharedKey.setKey(key, keyOffset, keyLength);
      sharedSignature.init(sharedKey, Signature.MODE_SIGN);

      return sharedSignature.sign(in, inOffset, inLength, out, outOffset);
    } else {
      byte[] block = JCSystem.makeTransientByteArray(BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);

      Util.arrayFillNonAtomic(block, (short) 0, BLOCK_SIZE, IPAD);

      for (short keyIndex = 0; keyIndex < keyLength; keyIndex++) {
        block[keyIndex] ^= key[(short) (keyOffset + keyIndex)];
      }

      sha512.update(block, (short) 0, BLOCK_SIZE);
      sha512.doFinal(in, inOffset, inLength, out, outOffset);

      Util.arrayFillNonAtomic(block, (short) 0, BLOCK_SIZE, OPAD);

      for (short keyIndex = 0; keyIndex < keyLength; keyIndex++) {
        block[keyIndex] ^= key[(short) (keyOffset + keyIndex)];
      }

      sha512.update(block, (short) 0, BLOCK_SIZE);
      return sha512.doFinal(out, outOffset, OUT_SIZE, out, outOffset);
    }
  }
}
