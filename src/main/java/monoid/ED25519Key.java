package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/** Expanded seed, valid only until deselection or explicit destruction. No secret export API. */
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
    Util.arrayFillNonAtomic(scalar, (short) 0, (short) scalar.length, (byte) 0);
    Util.arrayFillNonAtomic(prefix, (short) 0, (short) prefix.length, (byte) 0);
    Util.arrayFillNonAtomic(publicKey, (short) 0, (short) publicKey.length, (byte) 0);
  }
}
