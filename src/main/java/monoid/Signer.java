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

  public static byte[] signECDSADigest(WeierstrassCurve curve, Key privateKey, byte[] digest) {
    byte[] signature = OneShot.sign(Signature.SIG_CIPHER_ECDSA_PLAIN, privateKey, digest);

    LibECDSA.ensureLowS(curve.getR(), signature, (short) 0);

    return signature;
  }

  public static byte[] signED25519Message(
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

  public static byte[] signBIP340Digest(WeierstrassCurve curve, byte[] privateKey, byte[] digest) {
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
