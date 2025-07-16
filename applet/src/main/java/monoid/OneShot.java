package monoid;

import javacard.security.*;
import javacardx.crypto.*;

public final class OneShot {
  public static short sign(
      byte cipher,
      Key privateKey,
      byte[] in, short digestOffset, byte digestLength,
      byte[] out, short outOffset) {

    Signature.OneShot signature = Signature.OneShot.open(MessageDigest.ALG_SHA_256, cipher, Cipher.PAD_NULL);

    if (signature == null) {
      return signFallback(cipher, privateKey, in, digestOffset, digestLength, out, outOffset);
    }

    signature.init(privateKey, Signature.MODE_SIGN);

    short length = signature.signPreComputedHash(in, digestOffset, digestLength, out, outOffset);

    signature.close();

    return length;
  }

  private static short signFallback(
      byte cipher,
      Key privateKey,
      byte[] in, short digestOffset, byte digestLength,
      byte[] out, short outOffset) {

    Signature signature = Signature.getInstance(MessageDigest.ALG_SHA_256, cipher,
        Cipher.PAD_NULL, false);

    signature.init(privateKey, Signature.MODE_SIGN);

    return signature.signPreComputedHash(in, digestOffset, digestLength, out, outOffset);
  }

  public static short digest(
      byte algorithm,
      byte[] in, short dataOffset, short dataLength,
      byte[] out, short outOffset) {

    MessageDigest.OneShot digest = MessageDigest.OneShot.open(algorithm);

    if (digest == null) {
      return digestFallback(algorithm, in, dataOffset, dataLength, out, outOffset);
    }

    short length = digest.doFinal(
        in, dataOffset, dataLength,
        out, outOffset);

    digest.close();

    return length;
  }

  private static short digestFallback(
      byte algorithm,
      byte[] in, short dataOffset, short dataLength,
      byte[] out, short outOffset) {

    return MessageDigest
        .getInstance(algorithm, false)
        .doFinal(in, dataOffset, dataLength, out, outOffset);
  }
}
