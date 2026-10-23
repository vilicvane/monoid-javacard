package monoid;

import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import monoidlib.Utils;

/**
 * This is a utility class that provides OneShot fallback for JCardSim.
 */
public final class OneShot {

  public static byte[] sign(byte cipher, Key privateKey, byte[] digest) {
    Signature.OneShot signature = Signature.OneShot.open(
      MessageDigest.ALG_SHA_256,
      cipher,
      Cipher.PAD_NULL
    );

    if (signature == null) {
      // JCardSim doesn't support equivalent Signature yet (only a non-PLAIN one
      // that requires extra handling).
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
      return null;
    }

    try {
      signature.init(privateKey, Signature.MODE_SIGN);

      byte[] out = new byte[signature.getLength()];

      short length = signature.signPreComputedHash(
        digest,
        (short) 0,
        (short) digest.length,
        out,
        (short) 0
      );

      return length == out.length ? out : Utils.duplicateAsPersistent(out, (short) 0, length);
    } finally {
      signature.close();
    }
  }

  public static short digest(
    byte algorithm,
    byte[] in,
    short dataOffset,
    short dataLength,
    byte[] out,
    short outOffset
  ) {
    MessageDigest.OneShot digest = MessageDigest.OneShot.open(algorithm);

    if (digest == null) {
      return digestFallback(algorithm, in, dataOffset, dataLength, out, outOffset);
    }

    short length = digest.doFinal(in, dataOffset, dataLength, out, outOffset);

    digest.close();

    return length;
  }

  private static short digestFallback(
    byte algorithm,
    byte[] in,
    short dataOffset,
    short dataLength,
    byte[] out,
    short outOffset
  ) {
    return MessageDigest.getInstance(algorithm, false).doFinal(
      in,
      dataOffset,
      dataLength,
      out,
      outOffset
    );
  }

  public static void random(byte[] out, short outOffset, short outLength) {
    RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);

    if (random == null) {
      randomFallback(out, outOffset, outLength);
      return;
    }

    random.nextBytes(out, outOffset, outLength);
    random.close();
  }

  private static void randomFallback(byte[] out, short outOffset, short outLength) {
    RandomData.getInstance(RandomData.ALG_TRNG).nextBytes(out, outOffset, outLength);
  }
}
