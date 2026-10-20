package monoididentity;

import javacard.framework.Util;
import javacard.security.MessageDigest;

/** SHA-256 HMAC for the at-most-32-byte keys used by Identity. */
final class LibHMACSha256 {

  static final short BLOCK_LENGTH = 64;

  static void begin(MessageDigest digest, byte[] block, byte[] key, short offset, short length) {
    digest.reset();
    Util.arrayFillNonAtomic(block, (short) 0, BLOCK_LENGTH, (byte) 0x36);

    for (short index = 0; index < length; index++) {
      block[index] ^= key[(short) (offset + index)];
    }

    digest.update(block, (short) 0, BLOCK_LENGTH);
  }

  static void finish(MessageDigest digest, byte[] block, byte[] out, short offset) {
    for (short index = 0; index < BLOCK_LENGTH; index++) {
      block[index] ^= (byte) (0x36 ^ 0x5C);
    }

    digest.update(block, (short) 0, BLOCK_LENGTH);
    digest.doFinal(out, offset, MessageDigest.LENGTH_SHA_256, out, offset);
  }
}
