package monoid;

import javacard.framework.JCSystem;
import javacard.security.ECPrivateKey;

public abstract class Curve {

  // @formatter:off
  public static final byte[] SECP256k1 = {'s','e','c','p','2','5','6','k','1'};
  // @formatter:on

  public static Curve secp256k1;

  public static void init() {
    secp256k1 = new CurveSECP256k1();
  }

  public static void dispose() {
    secp256k1 = null;
  }

  public static void writeSupportedCurves(CBORWriter writer) {
    writer.array((short) 1);
    writer.text(SECP256k1);
  }

  public static Curve getSharedCurve(byte[] curveName) {
    if (Utils.equal(SECP256k1, curveName)) {
      return secp256k1;
    }

    return null;
  }

  public static Curve requireSharedCurve(byte[] curveName)
    throws CurveException {
    Curve curve = getSharedCurve(curveName);

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

  public abstract short derivePublicKey(
    ECPrivateKey privateKey,
    byte[] out,
    short outOffset
  );

  public byte[] derivePublicKey(ECPrivateKey privateKey) {
    byte[] publicKey = JCSystem.makeTransientByteArray(
      getPublicKeyLength(),
      JCSystem.CLEAR_ON_DESELECT
    );

    derivePublicKey(privateKey, publicKey, (short) 0);

    return publicKey;
  }
}
