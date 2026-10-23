// Generated from monoidlib/LibSecurity.java by Inplate.
package monoididentity;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public final class LibSecurity {

  public static final short SAFE_FALSE = (short) 0xA501;
  public static final short SAFE_TRUE = (short) 0x5AFE;

  private static final short CHECK_ROUNDS = 3;

  public interface Condition {
    boolean check();
  }

  public static short check(byte[] expected, byte[] actual, short conservativeResult) {
    if (conservativeResult != SAFE_FALSE && conservativeResult != SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    short completed = 0;
    short remaining = CHECK_ROUNDS;

    while (remaining != 0) {
      if (remaining < 1 || remaining > CHECK_ROUNDS) {
        return conservativeResult;
      }

      short result = SAFE_FALSE;

      if (expected != null && expected.length == actual.length) {
        short difference = 0;

        for (short index = 0; index < expected.length; index++) {
          difference |= expected[index] ^ actual[index];
        }

        result = difference == 0 ? SAFE_TRUE : SAFE_FALSE;
      }

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

    return (short) ~conservativeResult;
  }

  public static short check(Condition condition, short conservativeResult) {
    if (conservativeResult != SAFE_FALSE && conservativeResult != SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    short completed = 0;
    short remaining = CHECK_ROUNDS;

    while (remaining != 0) {
      if (remaining < 1 || remaining > CHECK_ROUNDS) {
        return conservativeResult;
      }

      short result = condition.check() ? SAFE_TRUE : SAFE_FALSE;

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
