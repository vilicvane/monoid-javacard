package monoid;

import javacard.framework.*;
import javacard.security.*;

public final class Signer {
  public static final byte[] CIPHER_ECDSA = {
      'e', 'c', 'd', 's', 'a' };

  public static void writeSupportedCiphers(CBORWriter writer) {
    writer.array((short) 1);
    writer.text(CIPHER_ECDSA);
  }

  public static byte[] sign(
      byte[] cipherType,
      Key privateKey,
      byte[] digest) throws SignerException {
    byte cipher;
    short length;

    if (Utils.equal(CIPHER_ECDSA, cipherType)) {
      cipher = Signature.SIG_CIPHER_ECDSA_PLAIN;
      length = (short) (privateKey.getSize() / 8 * 2);
    } else {
      SignerException.throwIt(SignerException.REASON_UNSUPPORTED_CIPHER);
      return null;
    }

    byte[] signature = JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);

    OneShot.sign(cipher, privateKey, digest, signature, (short) 0);

    LibECDSA.ensureLowS(signature, (short) 0);

    return signature;
  }
}
