package monoid;

import javacard.framework.JCSystem;

/** Expanded seed, valid only until deselection or explicit invalidation. */
public final class ED25519Key {

  final byte[] scalar = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
  final byte[] prefix = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
  final byte[] publicKey = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
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
