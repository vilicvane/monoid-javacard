package monoid;

import javacard.framework.JCSystem;
import javacard.security.Key;
import javacard.security.Signature;

public final class Signer {

  // @formatter:off
  public static final byte[] CIPHER_ECDSA = {'e','c','d','s','a'};
  public static final byte[] CIPHER_ED25519 = {'e','d','2','5','5','1','9'};
  public static final byte[] CIPHER_BIP340 = {'b','i','p','3','4','0'};

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

  public static byte[] signSchnorrDigest(WeierstrassCurve curve, byte[] privateKey, byte[] digest) {
    if (!(curve instanceof CurveSECP256k1)) {
      CurveException.throwIt(CurveException.REASON_UNSUPPORTED_CURVE);
      return null;
    }

    if (digest.length != CurveSECP256k1.KEY_LENGTH) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      return null;
    }

    byte[] auxiliary = JCSystem.makeTransientByteArray(
      CurveSECP256k1.KEY_LENGTH,
      JCSystem.CLEAR_ON_DESELECT
    );
    byte[] signature = JCSystem.makeTransientByteArray(
      LibBIP340.SIGNATURE_LENGTH,
      JCSystem.CLEAR_ON_DESELECT
    );

    OneShot.random(auxiliary, (short) 0, (short) auxiliary.length);
    LibBIP340.sign(
      (CurveSECP256k1) curve,
      privateKey,
      (short) 0,
      digest,
      (short) 0,
      (short) digest.length,
      auxiliary,
      (short) 0,
      signature,
      (short) 0
    );

    return signature;
  }
}
