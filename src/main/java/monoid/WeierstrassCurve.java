package monoid;

import javacard.security.ECPrivateKey;

public abstract class WeierstrassCurve {

  // @formatter:off
  public static final byte[] SECP256k1 = {'s','e','c','p','2','5','6','k','1'};
  public static final byte[] SECP256r1 = {'s','e','c','p','2','5','6','r','1'};
  // @formatter:on

  public static WeierstrassCurve secp256k1;
  public static WeierstrassCurve secp256r1;

  public static void init() {
    secp256k1 = new CurveSECP256k1();
    secp256r1 = new CurveSECP256r1();
  }

  public static void dispose() {
    secp256k1 = null;
    secp256r1 = null;
  }

  public static WeierstrassCurve getSharedCurve(byte[] curveName) {
    if (Utils.isEqual(SECP256k1, curveName)) {
      return secp256k1;
    } else if (Utils.isEqual(SECP256r1, curveName)) {
      return secp256r1;
    }

    return null;
  }

  public static WeierstrassCurve requireSharedCurve(byte[] curveName) throws CurveException {
    WeierstrassCurve curve = getSharedCurve(curveName);

    if (curve == null) {
      CurveException.throwIt(CurveException.REASON_UNSUPPORTED_CURVE);
      return null;
    }

    return curve;
  }

  public abstract byte[] getR();

  public abstract short getKeyLength();

  public abstract short getPublicKeyLength();

  public abstract ECPrivateKey getSharedPrivateKey(byte[] in, short keyOffset);

  public abstract short derivePublicKey(ECPrivateKey privateKey, byte[] out, short outOffset);

  public byte[] derivePublicKey(ECPrivateKey privateKey) {
    byte[] publicKey = new byte[getPublicKeyLength()];

    derivePublicKey(privateKey, publicKey, (short) 0);

    return publicKey;
  }
}
