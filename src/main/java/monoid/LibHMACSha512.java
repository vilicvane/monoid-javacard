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
  private static byte[] sharedBlock;

  public static void init() {
    try {
      sharedSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_512, true);
      sharedKey = (HMACKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_HMAC,
        (short) (OUT_BYTES * 8),
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
    sharedBlock = null;
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
    begin(key, keyOffset, keyLength);
    return finish(data, dataOffset, dataLength, out, outOffset);
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
    begin(key, keyOffset, keyLength, block);
    return finish(data, dataOffset, dataLength, out, outOffset, block);
  }

  /** A segmented operation must finish before another caller uses this shared engine. */
  static void begin(byte[] key, short offset, short length) {
    if ((sharedSignature == null || sharedKey == null) && sharedBlock == null) {
      sharedBlock = JCSystem.makeTransientByteArray(BLOCK_BYTES, JCSystem.CLEAR_ON_RESET);
    }

    begin(key, offset, length, sharedBlock);
  }

  static void begin(byte[] key, short offset, short length, byte[] block) {
    if (sharedSignature != null && sharedKey != null) {
      sharedKey.setKey(key, offset, length);
      sharedSignature.init(sharedKey, Signature.MODE_SIGN);
    } else {
      sharedDigest.reset();
      Util.arrayFillNonAtomic(block, (short) 0, BLOCK_BYTES, IPAD);

      for (short index = 0; index < length; index++) {
        block[index] ^= key[(short) (offset + index)];
      }

      sharedDigest.update(block, (short) 0, BLOCK_BYTES);
    }
  }

  static void update(byte[] data, short offset, short length) {
    if (sharedSignature != null && sharedKey != null) {
      sharedSignature.update(data, offset, length);
    } else {
      sharedDigest.update(data, offset, length);
    }
  }

  static short finish(
    byte[] data,
    short dataOffset,
    short dataLength,
    byte[] out,
    short outOffset
  ) {
    return finish(data, dataOffset, dataLength, out, outOffset, sharedBlock);
  }

  static short finish(
    byte[] data,
    short dataOffset,
    short dataLength,
    byte[] out,
    short outOffset,
    byte[] block
  ) {
    if (sharedSignature != null && sharedKey != null) {
      return sharedSignature.sign(data, dataOffset, dataLength, out, outOffset);
    } else {
      try {
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
    byte[] out = Utils.makePrivateByteArray(OUT_BYTES);

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
