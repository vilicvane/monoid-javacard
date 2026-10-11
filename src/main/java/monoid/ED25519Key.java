package monoid;

import javacard.framework.JCSystem;

/** Expanded seed, valid only until deselection or explicit destruction. No secret export API. */
public final class ED25519Key {

  final BigNat scalar;
  final byte[] prefix = ED25519Signer.transientBytes((short) 32);
  final byte[] publicKey = ED25519Signer.transientBytes((short) 32);
  private final byte[] valid = ED25519Signer.transientBytes((short) 1);

  ED25519Key(MathResources resources) {
    scalar = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, resources);
  }

  void activate() {
    valid[0] = 1;
  }

  boolean isValid() {
    return valid[0] != 0;
  }

  public void clear() {
    valid[0] = 0;
    scalar.erase();
    ED25519Signer.erase(prefix);
    ED25519Signer.erase(publicKey);
  }
}
