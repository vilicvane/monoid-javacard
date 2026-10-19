package monoid;

/** Persistent derivation result. Working keys are copied into operation-local storage. */
public final class DerivedKey {

  final byte[] key;
  byte[] expandedKey;

  private byte[] publicKey;

  DerivedKey(byte[] key) {
    this.key = Utils.duplicateAsPersistent(key);
  }

  public byte[] getKey() {
    return Utils.duplicateAsTransientReset(key);
  }

  public byte[] getPublicKey(WeierstrassCurve curve) {
    if (publicKey == null) {
      byte[] result = curve.derivePublicKey(curve.getSharedPrivateKey(key, (short) 0));
      publicKey = Utils.duplicateAsPersistent(result);

      return result;
    }

    return Utils.duplicateAsTransientReset(publicKey);
  }
}
