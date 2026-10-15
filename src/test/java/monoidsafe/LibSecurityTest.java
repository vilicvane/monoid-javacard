package monoidsafe;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LibSecurityTest {

  @Test
  public void falseIsConservativeForValidation() {
    assertResult(Constants.SAFE_FALSE, Constants.SAFE_TRUE, 3, true, true, true);
    assertResult(Constants.SAFE_FALSE, Constants.SAFE_FALSE, 1, false, true, true);
    assertResult(Constants.SAFE_FALSE, Constants.SAFE_FALSE, 2, true, false, true);
    assertResult(Constants.SAFE_FALSE, Constants.SAFE_FALSE, 3, true, true, false);
  }

  @Test
  public void trueIsConservativeForBlocking() {
    assertResult(Constants.SAFE_TRUE, Constants.SAFE_FALSE, 3, false, false, false);
    assertResult(Constants.SAFE_TRUE, Constants.SAFE_TRUE, 1, true, false, false);
    assertResult(Constants.SAFE_TRUE, Constants.SAFE_TRUE, 2, false, true, false);
    assertResult(Constants.SAFE_TRUE, Constants.SAFE_TRUE, 3, false, false, true);
  }

  @Test
  public void corruptedConservativeValuesCannotSelectAnotherPolicy() {
    for (short conservativeResult : new short[] { Constants.SAFE_FALSE, Constants.SAFE_TRUE }) {
      for (int bit = 0; bit < 16; bit++) {
        short corrupted = (short) (conservativeResult ^ (1 << bit));

        ISOException exception = Assertions.assertThrows(ISOException.class, () ->
          LibSecurity.check(
            () -> {
              Assertions.fail(
                "An invalid policy must be rejected before evaluating the condition."
              );
              return false;
            },
            corrupted
          )
        );

        Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
      }
    }
  }

  private void assertResult(
    short conservativeResult,
    short expected,
    int expectedCalls,
    boolean... values
  ) {
    int[] calls = new int[1];

    Assertions.assertEquals(
      expected,
      LibSecurity.check(() -> values[calls[0]++], conservativeResult)
    );
    Assertions.assertEquals(expectedCalls, calls[0]);
  }
}
