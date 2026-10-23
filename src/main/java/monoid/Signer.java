package monoid;

import javacard.security.Key;
import javacard.security.Signature;
import monoidlib.ByteSource;

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

    byte[] signature = new byte[LibED25519.SIGNATURE_LENGTH];

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

    byte[] auxiliary = new byte[CurveSECP256k1.KEY_LENGTH];
    byte[] signature = new byte[LibBIP340.SIGNATURE_LENGTH];

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
