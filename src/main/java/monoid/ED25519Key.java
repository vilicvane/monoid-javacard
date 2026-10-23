package monoid;

import javacard.framework.JCSystem;

/** Expanded seed, valid only until deselection or explicit invalidation. */
public final class ED25519Key {

  final byte[] scalar = new byte[32];
  final byte[] prefix = new byte[32];
  final byte[] publicKey = new byte[32];
  private final byte[] valid = JCSystem.makeTransientByteArray(
    (short) 1,
    JCSystem.CLEAR_ON_DESELECT
  );

  ED25519Key() {}

  void activate() {
    valid[0] = 1;
  }

  boolean isValid() {
    return valid[0] != 0;
  }

  public void clear() {
    valid[0] = 0;
  }
}
