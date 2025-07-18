package monoid;

import javacard.security.*;

public abstract class Curve {
  public static final byte[] SECP256k1 = {
      's', 'e', 'c', 'p', '2', '5', '6', 'k', '1'
  };

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

  public static Curve getSharedCurve(byte[] in, short curveOffset, byte curveLength) {
    if (Utils.equal(SECP256k1, in, curveOffset, curveLength)) {
      return secp256k1;
    }

    return null;
  }

  public static Curve requireSharedCurve(byte[] in, short typeOffset, byte typeLength) throws CurveException {
    Curve curve = getSharedCurve(in, typeOffset, typeLength);

    if (curve == null) {
      CurveException.throwIt(CurveException.REASON_UNSUPPORTED_CURVE);
      return null;
    }

    return curve;
  }

  public abstract byte[] getR();

  public abstract ECPrivateKey getSharedPrivateKey(byte[] in, short keyOffset);

  public abstract short derivePublicKey(ECPrivateKey privateKey, byte[] out, short outOffset);
}
