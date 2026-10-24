package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/** Shared synchronous HMAC engine backed by native message digests. */
final class HMAC {

  private MessageDigest sha1;
  private MessageDigest sha256;
  private MessageDigest sha512;

  private byte[] block;
  private final byte[] result = new byte[64];

  short getLength(byte algorithm) {
    switch (algorithm) {
      case Monoid.HMAC_SHA1:
        return 20;
      case Monoid.HMAC_SHA256:
        return 32;
      case Monoid.HMAC_SHA512:
        return 64;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);

        return 0;
    }
  }

  byte[] calculate(byte algorithm, byte[] key, byte[] message, short offset, short length) {
    short outputLength = getLength(algorithm);
    short blockLength = algorithm == Monoid.HMAC_SHA512 ? (short) 128 : 64;
    MessageDigest digest = getDigest(algorithm);

    if (block == null) {
      block = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_RESET);
    }

    digest.reset();

    try {
      Util.arrayFillNonAtomic(block, (short) 0, blockLength, (byte) 0x36);

      byte[] normalized = key;
      short keyLength = (short) key.length;

      if (keyLength > blockLength) {
        digest.doFinal(key, (short) 0, keyLength, result, (short) 0);
        normalized = result;
        keyLength = outputLength;
      }

      for (short index = 0; index < keyLength; index++) {
        block[index] ^= normalized[index];
      }

      digest.update(block, (short) 0, blockLength);
      digest.doFinal(message, offset, length, result, (short) 0);

      for (short index = 0; index < blockLength; index++) {
        block[index] ^= (byte) (0x36 ^ 0x5C);
      }

      digest.update(block, (short) 0, blockLength);
      digest.doFinal(result, (short) 0, outputLength, result, (short) 0);

      return result;
    } finally {
      digest.reset();
    }
  }

  private MessageDigest getDigest(byte algorithm) {
    switch (algorithm) {
      case Monoid.HMAC_SHA1:
        if (sha1 == null) {
          sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, true);
        }

        return sha1;
      case Monoid.HMAC_SHA256:
        if (sha256 == null) {
          sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
        }

        return sha256;
      case Monoid.HMAC_SHA512:
        if (sha512 == null) {
          sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, true);
        }

        return sha512;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);

        return null;
    }
  }
}
