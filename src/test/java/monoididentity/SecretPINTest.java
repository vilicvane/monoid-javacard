package monoididentity;

import static monoididentity.Constants.SAFE_FALSE;
import static monoididentity.Constants.SAFE_TRUE;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import main.ShareableSimulatorRuntime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

public class SecretPINTest {

  private static final byte[] PIN = "314159".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] NEW_PIN = "271828".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] WRONG_PIN = "000000".getBytes(StandardCharsets.US_ASCII);

  private CallerRuntime runtime;
  private CardSimulator simulator;
  private SecretPIN secretPIN;

  @BeforeEach
  public void initialize() {
    runtime = new CallerRuntime();
    simulator = new CardSimulator(runtime);
    runtime.caller = AIDUtil.create("f000000001");
    secretPIN = new SecretPIN();
  }

  @Test
  public void initializesOnceAndRequiresActualVerificationToUpdate() {
    Assertions.assertFalse(secretPIN.isSet());
    Assertions.assertFalse(secretPIN.check(PIN));
    Assertions.assertEquals(5, secretPIN.getTriesRemaining());
    secretPIN.update(PIN);
    Assertions.assertTrue(secretPIN.isSet());
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
    assertDenied(() -> secretPIN.update(NEW_PIN));
    Assertions.assertTrue(secretPIN.check(PIN));
    Assertions.assertEquals(SAFE_TRUE, secretPIN.getValidationResult());
  }

  @Test
  public void bindsAuthorizationToCallerObjectRatherThanAIDBytes() {
    authenticate();
    AID original = runtime.caller;
    runtime.caller = AIDUtil.create("f000000002");
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
    assertDenied(() -> secretPIN.update(NEW_PIN));
    runtime.caller = AIDUtil.create("f000000001");
    Assertions.assertTrue(runtime.caller.equals(original));
    Assertions.assertNotSame(original, runtime.caller);
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
    runtime.caller = null;
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
    runtime.caller = original;
    Assertions.assertEquals(SAFE_TRUE, secretPIN.getValidationResult());
  }

  @Test
  public void anotherCallerMustVerifyAndRevokesThePreviousCaller() {
    authenticate();
    AID original = runtime.caller;
    runtime.caller = AIDUtil.create("f000000002");
    Assertions.assertTrue(secretPIN.check(PIN));
    Assertions.assertEquals(SAFE_TRUE, secretPIN.getValidationResult());
    runtime.caller = original;
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
  }

  @Test
  public void PINComparisonRunsOnceAndEveryNativeValidationReadMustPass() throws Exception {
    secretPIN.update(PIN);

    for (int failure = 0; failure <= 3; failure++) {
      final int failedRead = failure;
      int[] calls = new int[2];
      OwnerPIN observed = new OwnerPIN(SecretPIN.PIN_TRY_LIMIT, SecretPIN.MAX_PIN_LENGTH) {
        @Override
        public boolean check(byte[] buffer, short offset, byte length) {
          calls[0]++;
          return super.check(buffer, offset, length);
        }

        @Override
        public boolean isValidated() {
          return super.isValidated() && ++calls[1] != failedRead;
        }
      };
      observed.update(PIN, (short) 0, (byte) PIN.length);
      field("pin").set(secretPIN, observed);

      if (failure == 0) {
        Assertions.assertTrue(secretPIN.check(PIN));
        Assertions.assertTrue(calls[1] >= 3);
      } else {
        assertDenied(() -> secretPIN.check(PIN));
        Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
      }

      Assertions.assertEquals(1, calls[0]);
    }
  }

  @Test
  public void acceptingCheckResultCannotOverrideRejectedNativeValidation() throws Exception {
    secretPIN.update(PIN);
    OwnerPIN observed = new OwnerPIN(SecretPIN.PIN_TRY_LIMIT, SecretPIN.MAX_PIN_LENGTH) {
      @Override
      public boolean check(byte[] buffer, short offset, byte length) {
        super.check(buffer, offset, length);
        return true;
      }
    };
    observed.update(PIN, (short) 0, (byte) PIN.length);
    field("pin").set(secretPIN, observed);

    assertDenied(() -> secretPIN.check(WRONG_PIN));
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
  }

  @Test
  public void rejectingCheckResultCannotLeaveAValidatedAuthorizationBehind() throws Exception {
    secretPIN.update(PIN);
    OwnerPIN observed = new OwnerPIN(SecretPIN.PIN_TRY_LIMIT, SecretPIN.MAX_PIN_LENGTH) {
      @Override
      public boolean check(byte[] buffer, short offset, byte length) {
        super.check(buffer, offset, length);
        return false;
      }
    };
    observed.update(PIN, (short) 0, (byte) PIN.length);
    field("pin").set(secretPIN, observed);

    Assertions.assertFalse(secretPIN.check(PIN));
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
  }

  @Test
  public void initializationRequiresEveryStateReadToRemainUnset() throws Exception {
    Field validation = field("pinSetValidation");
    LibSecurity.Condition original = (LibSecurity.Condition) validation.get(secretPIN);

    for (int failure = 1; failure <= 3; failure++) {
      final int failedRead = failure;
      int[] calls = new int[1];
      validation.set(
        secretPIN,
        (LibSecurity.Condition) () -> ++calls[0] == failedRead || original.check()
      );
      assertDenied(() -> secretPIN.update(PIN));
      validation.set(secretPIN, original);
      Assertions.assertFalse(secretPIN.isSet());
    }
  }

  @Test
  public void wrongPINConsumesOneAttemptAndRevokesAuthorization() {
    authenticate();
    Assertions.assertFalse(secretPIN.check(WRONG_PIN));
    Assertions.assertEquals(4, secretPIN.getTriesRemaining());
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
    Assertions.assertTrue(secretPIN.check(PIN));
    Assertions.assertEquals(5, secretPIN.getTriesRemaining());
  }

  @Test
  public void exhaustedAttemptsPreventAuthenticationAndChanges() {
    authenticate();

    for (int remaining = 4; remaining >= 0; remaining--) {
      Assertions.assertFalse(secretPIN.check(WRONG_PIN));
      Assertions.assertEquals(remaining, secretPIN.getTriesRemaining());
      Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
    }

    Assertions.assertFalse(secretPIN.check(PIN));
    assertDenied(() -> secretPIN.update(NEW_PIN));
  }

  @Test
  public void anyBlockedReadDeniesAuthorization() throws Exception {
    authenticate();
    Field validation = field("pinBlockedValidation");
    LibSecurity.Condition original = (LibSecurity.Condition) validation.get(secretPIN);

    for (int failure = 1; failure <= 3; failure++) {
      final int blockedRead = failure;
      int[] calls = new int[1];
      validation.set(
        secretPIN,
        (LibSecurity.Condition) () -> ++calls[0] == blockedRead || original.check()
      );
      Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
      Assertions.assertEquals(blockedRead, calls[0]);
    }

    validation.set(secretPIN, original);
    Assertions.assertEquals(5, secretPIN.getTriesRemaining());
    Assertions.assertEquals(SAFE_TRUE, secretPIN.getValidationResult());
  }

  @Test
  public void updatesRevokeAuthorizationAndRequireTheNewPIN() {
    authenticate();
    secretPIN.update(NEW_PIN);
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
    Assertions.assertFalse(secretPIN.check(PIN));
    Assertions.assertTrue(secretPIN.check(NEW_PIN));
  }

  @Test
  public void failedUpdatesRevokeAuthorizationAndEndTheirTransaction() {
    authenticate();
    Assertions.assertThrows(javacard.framework.PINException.class, () ->
      secretPIN.update(new byte[SecretPIN.MAX_PIN_LENGTH + 1])
    );
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
    Assertions.assertTrue(secretPIN.check(PIN));
  }

  @Test
  public void nativeValidationCannotBeReplacedByTheEncodedAuthorization() throws Exception {
    authenticate();
    ((OwnerPIN) field("pin").get(secretPIN)).reset();
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
    assertDenied(() -> secretPIN.update(NEW_PIN));
  }

  @Test
  public void clearAndCardResetRevokeAuthorization() {
    authenticate();
    secretPIN.clearAuth();
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
    Assertions.assertTrue(secretPIN.check(PIN));
    simulator.reset();
    Assertions.assertEquals(SAFE_FALSE, secretPIN.getValidationResult());
    Assertions.assertTrue(secretPIN.isSet());
    Assertions.assertTrue(secretPIN.check(PIN));
  }

  @Test
  public void rejectsSingleBitChangesInAuthorization() throws Exception {
    authenticate();
    short[] auth = (short[]) field("auth").get(secretPIN);

    for (short[] valid : new short[][] { new short[2], auth.clone() }) {
      for (int word = 0; word < auth.length; word++) {
        for (int bit = 0; bit < 16; bit++) {
          System.arraycopy(valid, 0, auth, 0, auth.length);
          auth[word] ^= (short) (1 << bit);
          assertDenied(() -> secretPIN.getValidationResult());
          assertDenied(() -> secretPIN.update(NEW_PIN));
        }
      }
    }
  }

  @Test
  public void corruptSetStateCannotBypassInitializationOrAuthorization() throws Exception {
    Field state = field("pinState");
    Field inverse = field("pinStateInverse");

    for (boolean initialized : new boolean[] { false, true }) {
      if (initialized) {
        authenticate();
      }

      short validState = state.getShort(secretPIN);
      short validInverse = inverse.getShort(secretPIN);

      for (Field target : new Field[] { state, inverse }) {
        for (int bit = 0; bit < 16; bit++) {
          state.setShort(secretPIN, validState);
          inverse.setShort(secretPIN, validInverse);
          target.setShort(secretPIN, (short) (target.getShort(secretPIN) ^ (1 << bit)));
          assertDenied(() -> secretPIN.isSet());
          assertDenied(() -> secretPIN.update(NEW_PIN));
        }
      }

      state.setShort(secretPIN, validState);
      inverse.setShort(secretPIN, validInverse);
    }
  }

  private void authenticate() {
    secretPIN.update(PIN);
    Assertions.assertTrue(secretPIN.check(PIN));
  }

  private Field field(String name) throws Exception {
    Field field = SecretPIN.class.getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private void assertDenied(Executable operation) {
    ISOException exception = Assertions.assertThrows(ISOException.class, operation);
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
  }

  private static final class CallerRuntime extends ShareableSimulatorRuntime {

    private AID caller;

    @Override
    public AID getPreviousContextAID() {
      return caller;
    }
  }
}
