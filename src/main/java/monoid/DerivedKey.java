package monoid;

import javacard.framework.Util;
import monoidlib.Utils;

/** Persistent derivation result. Working keys are copied into operation-local storage. */
public final class DerivedKey {

  final byte[] key;
  byte[] expandedKey;

  private byte[] publicKey;
  private byte[] uncompressedPublicKey;

  DerivedKey(byte[] key) {
    this.key = Utils.duplicateAsPersistent(key);
  }

  public byte[] getKey() {
    return Utils.duplicateAsPersistent(key);
  }

  public byte[] getPublicKey(WeierstrassCurve curve) {
    if (publicKey == null) {
      byte[] result;

      if (uncompressedPublicKey != null) {
        result = new byte[33];
        result[0] = (byte) (2 | (uncompressedPublicKey[64] & 1));
        Util.arrayCopyNonAtomic(uncompressedPublicKey, (short) 1, result, (short) 1, (short) 32);
      } else {
        result = curve.derivePublicKey(curve.getSharedPrivateKey(key, (short) 0));
      }
      publicKey = Utils.duplicateAsPersistent(result);

      return result;
    }

    return Utils.duplicateAsPersistent(publicKey);
  }

  byte[] getUncompressedPublicKey(CurveSECP256r1 curve) {
    if (uncompressedPublicKey == null) {
      byte[] result = new byte[65];
      curve.deriveUncompressedPublicKey(
        curve.getSharedPrivateKey(key, (short) 0),
        result,
        (short) 0
      );
      uncompressedPublicKey = result;
    }

    return uncompressedPublicKey;
  }
}
