package monoid;

import javacard.framework.JCSystem;
import javacard.security.Key;
import javacard.security.Signature;

public final class Signer {

  // @formatter:off
  public static final byte[] CIPHER_ECDSA = {'e','c','d','s','a'};
  public static final byte[] CIPHER_EDDSA = {'e','d','d','s','a'};

  // @formatter:on

  public static byte[] signECDSADigest(byte[] cipherType, Key privateKey, byte[] digest)
    throws SignerException {
    byte cipher;
    short bufferLength;

    if (Utils.isEqual(CIPHER_ECDSA, cipherType)) {
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

  public static byte[] signEDDSAMessage(
    EdwardsCurve curve,
    ED25519Key privateKey,
    ByteSource message,
    short messageOffset,
    short messageLength
  ) {
    if (!(curve instanceof CurveED25519)) {
      CurveException.throwIt(CurveException.REASON_UNSUPPORTED_CURVE);
      return null;
    }

    byte[] signature = JCSystem.makeTransientByteArray(
      LibED25519.SIGNATURE_LENGTH,
      JCSystem.CLEAR_ON_DESELECT
    );

    LibED25519.sign(
      (CurveED25519) curve,
      privateKey,
      message,
      messageOffset,
      messageLength,
      signature,
      (short) 0
    );

    return signature;
  }
}
