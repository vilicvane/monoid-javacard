package monoidlib;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LibSecurityTest {

  @Test
  public void arraysRequireEveryByteToMatch() {
    byte[] expected = new byte[32];

    for (int index = 0; index < expected.length; index++) {
      expected[index] = (byte) (index * 17);
    }

    for (short conservativeResult : new short[] { LibSecurity.SAFE_FALSE, LibSecurity.SAFE_TRUE }) {
      Assertions.assertEquals(
        LibSecurity.SAFE_TRUE,
        LibSecurity.check(expected, expected.clone(), conservativeResult)
      );

      for (int index = 0; index < expected.length; index++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] actual = expected.clone();
          actual[index] ^= (byte) (1 << bit);

          Assertions.assertEquals(
            LibSecurity.SAFE_FALSE,
            LibSecurity.check(expected, actual, conservativeResult)
          );
        }
      }

      byte[] actual = expected.clone();
      actual[0] ^= (byte) 0x80;
      actual[31] ^= (byte) 0x80;

      Assertions.assertEquals(
        LibSecurity.SAFE_FALSE,
        LibSecurity.check(expected, actual, conservativeResult)
      );
    }
  }

  @Test
  public void missingOrDifferentLengthBindingsDoNotMatch() {
    for (short conservativeResult : new short[] { LibSecurity.SAFE_FALSE, LibSecurity.SAFE_TRUE }) {
      Assertions.assertEquals(
        LibSecurity.SAFE_FALSE,
        LibSecurity.check(null, new byte[32], conservativeResult)
      );
      Assertions.assertEquals(
        LibSecurity.SAFE_FALSE,
        LibSecurity.check(new byte[32], new byte[31], conservativeResult)
      );
      Assertions.assertEquals(
        LibSecurity.SAFE_FALSE,
        LibSecurity.check(new byte[32], new byte[33], conservativeResult)
      );
    }
  }

  @Test
  public void falseIsConservativeForValidation() {
    assertResult(LibSecurity.SAFE_FALSE, LibSecurity.SAFE_TRUE, 3, true, true, true);
    assertResult(LibSecurity.SAFE_FALSE, LibSecurity.SAFE_FALSE, 1, false, true, true);
    assertResult(LibSecurity.SAFE_FALSE, LibSecurity.SAFE_FALSE, 2, true, false, true);
    assertResult(LibSecurity.SAFE_FALSE, LibSecurity.SAFE_FALSE, 3, true, true, false);
  }

  @Test
  public void trueIsConservativeForBlocking() {
    assertResult(LibSecurity.SAFE_TRUE, LibSecurity.SAFE_FALSE, 3, false, false, false);
    assertResult(LibSecurity.SAFE_TRUE, LibSecurity.SAFE_TRUE, 1, true, false, false);
    assertResult(LibSecurity.SAFE_TRUE, LibSecurity.SAFE_TRUE, 2, false, true, false);
    assertResult(LibSecurity.SAFE_TRUE, LibSecurity.SAFE_TRUE, 3, false, false, true);
  }

  @Test
  public void corruptedConservativeValuesCannotSelectAnotherPolicy() {
    for (short conservativeResult : new short[] { LibSecurity.SAFE_FALSE, LibSecurity.SAFE_TRUE }) {
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

        exception = Assertions.assertThrows(ISOException.class, () ->
          LibSecurity.check(new byte[32], new byte[32], corrupted)
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
