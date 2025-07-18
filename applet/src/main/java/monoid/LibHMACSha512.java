package monoid;

import javacard.framework.*;
import javacard.security.*;

public final class LibHMACSha512 {
  private static final byte IPAD = (byte) 0x36;
  private static final byte OPAD = (byte) 0x5c;

  private static final short BLOCK_BYTES = (short) 128;
  private static final short OUT_BYTES = (short) 64;

  private static Signature sharedSignature;
  private static HMACKey sharedKey;
  private static MessageDigest sharedDigest;

  public static void init() {
    try {
      sharedSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
      sharedKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
          KeyBuilder.LENGTH_AES_256, false);
    } catch (Exception e) {
      sharedSignature = null;
      sharedKey = null;
      sharedDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
    }
  }

  public static void dispose() {
    sharedSignature = null;
    sharedKey = null;
    sharedDigest = null;
  }

  public static short digest(
      byte[] key, short keyOffset, short keyLength,
      byte[] data, short dataOffset, short dataLength,
      byte[] out, short outOffset) {
    if (sharedSignature != null && sharedKey != null) {
      sharedKey.setKey(key, keyOffset, keyLength);
      sharedSignature.init(sharedKey, Signature.MODE_SIGN);

      return sharedSignature.sign(data, dataOffset, dataLength, out, outOffset);
    } else {
      byte[] block = JCSystem.makeTransientByteArray(BLOCK_BYTES, JCSystem.CLEAR_ON_DESELECT);

      Util.arrayFillNonAtomic(block, (short) 0, BLOCK_BYTES, IPAD);

      for (short keyIndex = 0; keyIndex < keyLength; keyIndex++) {
        block[keyIndex] ^= key[(short) (keyOffset + keyIndex)];
      }

      sharedDigest.update(block, (short) 0, BLOCK_BYTES);
      sharedDigest.doFinal(data, dataOffset, dataLength, out, outOffset);

      Util.arrayFillNonAtomic(block, (short) 0, BLOCK_BYTES, OPAD);

      for (short keyIndex = 0; keyIndex < keyLength; keyIndex++) {
        block[keyIndex] ^= key[(short) (keyOffset + keyIndex)];
      }

      sharedDigest.update(block, (short) 0, BLOCK_BYTES);
      return sharedDigest.doFinal(out, outOffset, OUT_BYTES, out, outOffset);
    }
  }
}
