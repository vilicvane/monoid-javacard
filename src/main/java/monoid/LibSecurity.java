package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public final class LibSecurity {

  private static final short CHECK_ROUNDS = 3;

  public interface Condition {
    boolean check();
  }

  public static short check(Condition condition, short conservativeResult) {
    if (conservativeResult != Constants.SAFE_FALSE && conservativeResult != Constants.SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    short completed = 0;
    short remaining = CHECK_ROUNDS;

    while (remaining != 0) {
      if (remaining < 1 || remaining > CHECK_ROUNDS) {
        return conservativeResult;
      }

      short result = condition.check() ? Constants.SAFE_TRUE : Constants.SAFE_FALSE;

      if (result == conservativeResult) {
        return conservativeResult;
      }

      completed++;
      remaining--;
    }

    if (completed != CHECK_ROUNDS) {
      return conservativeResult;
    }

    if (remaining != 0) {
      return conservativeResult;
    }

    // The encodings are complements; an invalid value stays invalid when inverted.
    return (short) ~conservativeResult;
  }
}
