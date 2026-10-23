package monoid;

import monoidlib.Utils;

public abstract class EdwardsCurve {

  // @formatter:off
  public static final byte[] ED25519 = {'e','d','2','5','5','1','9'};

  // @formatter:on

  public static EdwardsCurve ed25519;

  public static void init() {
    ed25519 = new CurveED25519();
  }

  public static void dispose() {
    ed25519 = null;
  }

  public static EdwardsCurve getSharedCurve(byte[] curveName) {
    if (Utils.isEqual(ED25519, curveName)) {
      return ed25519;
    }

    return null;
  }

  public static EdwardsCurve requireSharedCurve(byte[] curveName) throws CurveException {
    EdwardsCurve curve = getSharedCurve(curveName);

    if (curve == null) {
      CurveException.throwIt(CurveException.REASON_UNSUPPORTED_CURVE);
      return null;
    }

    return curve;
  }

  public abstract short getKeyLength();

  public abstract short getPublicKeyLength();

  public abstract ED25519Key getSharedPrivateKey(byte[] in, short keyOffset);

  public abstract ED25519Key getSharedPrivateKey(DerivedKey key);

  public abstract short derivePublicKey(ED25519Key privateKey, byte[] out, short outOffset);

  public byte[] derivePublicKey(ED25519Key privateKey) {
    byte[] publicKey = new byte[getPublicKeyLength()];

    derivePublicKey(privateKey, publicKey, (short) 0);

    return publicKey;
  }
}
