package monoid;

import javacard.security.*;

public final class Signer {
  public static final byte[] CIPHER_ECDSA = {
      'e', 'c', 'd', 's', 'a' };

  public static void writeSupportedCiphers(CBORWriter writer) {
    writer.array((short) 1);
    writer.text(CIPHER_ECDSA);
  }

  public static short sign(
      byte[] cipherIn, short cipherOffset, byte cipherLength,
      Key privateKey,
      byte[] in, short digestOffset, byte digestLength,
      byte[] out, short outOffset) throws SignerException {
    byte cipher;

    if (Utils.equal(CIPHER_ECDSA, cipherIn, cipherOffset, cipherLength)) {
      cipher = Signature.SIG_CIPHER_ECDSA_PLAIN;
    } else {
      SignerException.throwIt(SignerException.REASON_UNSUPPORTED_CIPHER);
      return 0;
    }

    short length = OneShot.sign(cipher, privateKey, in, digestOffset, digestLength, out, outOffset);

    LibECDSA.ensureLowS(out, outOffset);

    return length;
  }
}
