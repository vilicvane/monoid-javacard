package monoid;

import javacard.framework.JCSystem;
import javacard.security.Key;
import javacard.security.Signature;

public final class Signer {

  // @formatter:off
  public static final byte[] CIPHER_ECDSA = {'e','c','d','s','a'};

  // @formatter:on

  public static void writeSupportedCiphers(CBORWriter writer) {
    writer.array((short) 1);
    writer.text(CIPHER_ECDSA);
  }

  public static byte[] sign(byte[] cipherType, Key privateKey, byte[] digest)
    throws SignerException {
    byte cipher;
    short bufferLength;

    if (Utils.equal(CIPHER_ECDSA, cipherType)) {
      cipher = Signature.SIG_CIPHER_ECDSA_PLAIN;

      // Signature length is 2 * (key size / 8), + 1 for case that key size is
      // not divisible by 8, + 10 for ASN.1 encoding overhead.
      bufferLength = (short) ((privateKey.getSize() / 8 + 1) * 2 + 10);
    } else {
      SignerException.throwIt(SignerException.REASON_UNSUPPORTED_CIPHER);
      return null;
    }

    byte[] signature = JCSystem.makeTransientByteArray(bufferLength, JCSystem.CLEAR_ON_DESELECT);

    short length = OneShot.sign(cipher, privateKey, digest, signature, (short) 0);

    LibECDSA.ensureLowS(signature, (short) 0);

    return Utils.duplicateAsTransientDeselect(signature, (short) 0, length);
  }
}
