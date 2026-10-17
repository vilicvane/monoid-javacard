package monoid;

import static monoidsafe.Constants.SAFE_FALSE;
import static monoidsafe.Constants.SAFE_TRUE;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import javacard.framework.AID;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoidsafe.MonoidSafeApplet;
import monoidsafe.SafeShareable;
import monoidsafeidentity.MonoidSafeIdentityApplet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

public class CommandAuthenticationTest {

  private static final AID MONOID_SAFE_IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_IDENTITY_AID}}"
    "f06d6f6e6f696400010000"
  );
  private static final AID MONOID_SAFE_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_AID}}"
    "f06d6f6e6f696401010000"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f696402010000"
  );

  private static final byte[] PIN = "314159".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] NEW_PIN = "271828".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] WRONG_PIN = "000000".getBytes(StandardCharsets.US_ASCII);

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    resetAppletState();

    simulator = new CardSimulator(new ShareableSimulatorRuntime());
    simulator.installApplet(MONOID_SAFE_IDENTITY_AID, MonoidSafeIdentityApplet.class);
    simulator.installApplet(MONOID_SAFE_AID, MonoidSafeApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    selectMonoid();
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(MONOID_AID);
    simulator.deleteApplet(MONOID_SAFE_AID);
    simulator.deleteApplet(MONOID_SAFE_IDENTITY_AID);
    resetAppletState();
  }

  @Test
  public void initializesBothPINsFromClearedAuthorization() throws Exception {
    Assertions.assertArrayEquals(new short[2], authorization());
    Assertions.assertEquals(0, Command.getAuth());
    assertError(setPIN(PIN, false), MonoidException.CODE_SAFE_PIN_NOT_SET);
    assertException(() -> MonoidApplet.updatePIN(PIN), MonoidException.CODE_SAFE_PIN_NOT_SET);
    Assertions.assertEquals(SAFE_FALSE, MonoidApplet.getPINSetResult(SAFE_TRUE));
    Assertions.assertFalse(MonoidApplet.safe.isPINSet());

    initializePINs();
    Assertions.assertEquals(SAFE_TRUE, MonoidApplet.getPINSetResult(SAFE_FALSE));
    Assertions.assertTrue(MonoidApplet.safe.isPINSet());
    Assertions.assertEquals(0, Command.getAuth());
    assertPINs(PIN, PIN);
  }

  @Test
  public void accessAuthorizationCannotChangeEitherPIN() {
    initializePINs();
    assertSuccess(authenticate(PIN, false));
    Assertions.assertEquals(Command.AUTH_ACCESS, Command.requireAuth(Command.AUTH_ACCESS));
    assertException(
      () -> Command.requireAuth(Command.AUTH_SAFE),
      MonoidException.CODE_ACCESS_DENIED
    );
    assertUnknownPermissionsDenied();

    assertError(setPIN(NEW_PIN, false), MonoidException.CODE_ACCESS_DENIED);
    assertError(setPIN(NEW_PIN, true), MonoidException.CODE_ACCESS_DENIED);
    assertPINs(PIN, PIN);
  }

  @Test
  public void safeAuthorizationCanChangeBothPINs() {
    initializePINs();
    assertSuccess(authenticate(PIN, true));
    Assertions.assertEquals(Command.AUTH_SAFE, Command.requireAuth(Command.AUTH_ACCESS));
    Assertions.assertEquals(Command.AUTH_SAFE, Command.requireAuth(Command.AUTH_SAFE));
    assertUnknownPermissionsDenied();

    assertSuccess(setPIN(NEW_PIN, false));
    assertSuccess(setPIN(NEW_PIN, true));
    assertPINs(NEW_PIN, NEW_PIN);
  }

  @Test
  public void directPINUpdatesRequireUserSafeAuthorization() {
    initializePINs();

    // The cached Safe PIN can validate storage access without authenticating the user.
    MonoidApplet.checkSafeUnlocked();
    assertException(() -> MonoidApplet.updatePIN(NEW_PIN), MonoidException.CODE_UNAUTHORIZED);
    assertException(() -> MonoidApplet.updateSafePIN(NEW_PIN), MonoidException.CODE_UNAUTHORIZED);

    assertSuccess(authenticate(PIN, false));
    assertException(() -> MonoidApplet.updatePIN(NEW_PIN), MonoidException.CODE_ACCESS_DENIED);
    assertException(() -> MonoidApplet.updateSafePIN(NEW_PIN), MonoidException.CODE_ACCESS_DENIED);
    assertPINs(PIN, PIN);
  }

  @Test
  public void PINUpdatesRecheckAuthorizationAfterEntry() throws Exception {
    initializePINs();
    short[] auth = authorization();

    for (boolean safePIN : new boolean[] { false, true }) {
      for (boolean corrupt : new boolean[] { false, true }) {
        assertSuccess(authenticate(PIN, true));
        MonoidApplet.checkPINUpdate();

        if (corrupt) {
          auth[1] ^= 1;
        } else {
          assertSuccess(authenticate(PIN, false));
        }

        assertException(
          () -> {
            if (safePIN) {
              MonoidApplet.updateSafePIN(NEW_PIN);
            } else {
              MonoidApplet.updatePIN(NEW_PIN);
            }
          },
          corrupt ? MonoidException.CODE_UNAUTHORIZED : MonoidException.CODE_ACCESS_DENIED
        );
      }
    }

    assertPINs(PIN, PIN);
  }

  @Test
  public void rejectsEverySingleBitChangeInStoredAuthorization() throws Exception {
    initializePINs();
    short[] auth = authorization();

    for (short state : new short[] { 0, Command.AUTH_ACCESS, Command.AUTH_SAFE }) {
      resetAndSelect();

      if (state != 0) {
        assertSuccess(authenticate(PIN, state == Command.AUTH_SAFE));
      }

      short[] valid = auth.clone();

      for (int word = 0; word < auth.length; word++) {
        for (int bit = 0; bit < 16; bit++) {
          System.arraycopy(valid, 0, auth, 0, auth.length);
          auth[word] ^= (short) (1 << bit);

          assertException(Command::getAuth, MonoidException.CODE_UNAUTHORIZED);
          assertException(
            () -> Command.requireAuth(Command.AUTH_ACCESS),
            MonoidException.CODE_UNAUTHORIZED
          );
          assertException(
            () -> Command.requireAuth(Command.AUTH_SAFE),
            MonoidException.CODE_UNAUTHORIZED
          );
        }
      }
    }
  }

  @Test
  public void rejectsInvalidCodesEvenWhenTheirComplementsMatch() throws Exception {
    short[] auth = authorization();

    for (short invalid : new short[] { 0, 1, 3, -1, 0x5A5A }) {
      auth[0] = invalid;
      auth[1] = (short) ~invalid;

      assertException(Command::getAuth, MonoidException.CODE_UNAUTHORIZED);
      assertError(setPIN(PIN, true), MonoidException.CODE_UNAUTHORIZED);
      Assertions.assertEquals(SAFE_FALSE, MonoidApplet.getPINSetResult(SAFE_TRUE));
      Assertions.assertFalse(MonoidApplet.safe.isPINSet());
    }
  }

  @Test
  public void damagedPINStateCannotPermitAuthenticationOrPINUpdates() throws Exception {
    Field state = MonoidApplet.class.getDeclaredField("pinState");
    Field inverse = MonoidApplet.class.getDeclaredField("pinStateInverse");
    state.setAccessible(true);
    inverse.setAccessible(true);

    for (boolean initialized : new boolean[] { false, true }) {
      if (initialized) {
        initializePINs();
        assertSuccess(authenticate(PIN, true));
      }

      short validState = state.getShort(null);
      short validInverse = inverse.getShort(null);

      try {
        for (Field field : new Field[] { state, inverse }) {
          for (int bit = 0; bit < 16; bit++) {
            state.setShort(null, validState);
            inverse.setShort(null, validInverse);
            field.setShort(null, (short) (field.getShort(null) ^ (1 << bit)));

            assertDamagedPINStateDenied();
          }
        }

        for (short invalid : new short[] { 0, 1, -1, 0x5A5A }) {
          state.setShort(null, invalid);
          inverse.setShort(null, (short) ~invalid);

          assertDamagedPINStateDenied();
        }
      } finally {
        state.setShort(null, validState);
        inverse.setShort(null, validInverse);
      }

      if (initialized) {
        assertPINs(PIN, PIN);
      } else {
        Assertions.assertFalse(MonoidApplet.safe.isPINSet());
      }
    }
  }

  @Test
  public void rejectedPINUpdateEndsItsTransactionAndPreservesPINState() {
    initializePINs();
    assertSuccess(authenticate(PIN, true));

    Assertions.assertThrows(javacard.framework.PINException.class, () ->
      MonoidApplet.updatePIN(new byte[MonoidApplet.MAX_PIN_LENGTH + 1])
    );
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
    Assertions.assertEquals(SAFE_TRUE, MonoidApplet.getPINSetResult(SAFE_FALSE));
    assertPINs(PIN, PIN);

    assertSuccess(setPIN(NEW_PIN, false));
    assertPINs(NEW_PIN, PIN);
  }

  @Test
  public void resetAndDeselectClearAuthorization() throws Exception {
    initializePINs();

    for (boolean reset : new boolean[] { false, true }) {
      assertSuccess(authenticate(PIN, true));

      if (reset) {
        simulator.reset();
      } else {
        Assertions.assertTrue(simulator.selectApplet(MONOID_SAFE_AID));
      }

      selectMonoid();
      Assertions.assertArrayEquals(new short[2], authorization());
      assertException(
        () -> Command.requireAuth(Command.AUTH_ACCESS),
        MonoidException.CODE_UNAUTHORIZED
      );
      assertError(setPIN(NEW_PIN, false), MonoidException.CODE_UNAUTHORIZED);
    }
  }

  @Test
  public void incorrectPINConsumesOneAttemptAndPreservesExistingAuthorization() {
    initializePINs();

    for (boolean safePIN : new boolean[] { false, true }) {
      assertSuccess(authenticate(PIN, true));

      for (short remaining = 4; remaining >= 3; remaining--) {
        CBORBufferReader reader = assertError(
          authenticate(WRONG_PIN, safePIN),
          MonoidException.CODE_INVALID_PIN
        );
        Assertions.assertEquals(remaining, reader.requireKey(Text.tries).integer());
        Assertions.assertEquals(
          remaining,
          safePIN ? MonoidApplet.safe.getPINTriesRemaining() : MonoidApplet.pin.getTriesRemaining()
        );
        Assertions.assertEquals(Command.AUTH_SAFE, Command.getAuth());
      }
    }
  }

  @Test
  public void accessPINValidationMustPassEveryReadBeforeGrantingAuthorization() {
    initializePINs();

    for (int failedRead = 0; failedRead <= 3; failedRead++) {
      resetAndSelect();
      final int failure = failedRead;
      int[] calls = new int[2];
      OwnerPIN observed = new OwnerPIN(MonoidApplet.PIN_TRY_LIMIT, MonoidApplet.MAX_PIN_LENGTH) {
        @Override
        public boolean check(byte[] buffer, short offset, byte length) {
          calls[0]++;
          return super.check(buffer, offset, length);
        }

        @Override
        public boolean isValidated() {
          if (calls[0] == 0) {
            return super.isValidated();
          }

          calls[1]++;
          return super.isValidated() && calls[1] != failure;
        }
      };
      observed.update(PIN, (short) 0, (byte) PIN.length);
      MonoidApplet.pin = observed;

      ResponseAPDU response = authenticate(PIN, false);
      Assertions.assertEquals(1, calls[0]);
      Assertions.assertEquals(failedRead == 0 ? 3 : failedRead, calls[1]);

      if (failedRead == 0) {
        assertSuccess(response);
        Assertions.assertEquals(Command.AUTH_ACCESS, Command.getAuth());
      } else {
        assertError(response, MonoidException.CODE_UNAUTHORIZED);
        Assertions.assertEquals(0, Command.getAuth());
      }
    }
  }

  @Test
  public void safeValidationIsRecheckedWithoutRepeatingPINComparison() throws Exception {
    initializePINs();
    Field field = Safe.class.getDeclaredField("safe");
    field.setAccessible(true);
    SafeShareable original = (SafeShareable) field.get(MonoidApplet.safe);

    for (boolean unlock : new boolean[] { false, true }) {
      for (int failedRead = 0; failedRead <= 3; failedRead++) {
        resetAndSelect();
        MonoidApplet.safePIN = PIN.clone();
        final int failure = failedRead;
        int[] calls = new int[2];
        SafeShareable observed = (SafeShareable) Proxy.newProxyInstance(
          SafeShareable.class.getClassLoader(),
          new Class<?>[] { SafeShareable.class },
          (proxy, method, arguments) -> {
            if (method.getName().equals("checkPIN")) {
              calls[0]++;
            } else if (method.getName().equals("isPINValidated")) {
              calls[1]++;

              if (calls[1] == failure) {
                return false;
              }
            }

            try {
              return method.invoke(original, arguments);
            } catch (InvocationTargetException exception) {
              throw exception.getCause();
            }
          }
        );
        field.set(MonoidApplet.safe, observed);

        if (unlock) {
          if (failedRead == 0) {
            MonoidApplet.checkSafeUnlocked();
          } else {
            assertException(MonoidApplet::checkSafeUnlocked, MonoidException.CODE_SAFE_LOCKED);
            Assertions.assertNull(MonoidApplet.safePIN);
          }

          Assertions.assertEquals(0, Command.getAuth());
        } else {
          ResponseAPDU response = authenticate(PIN, true);

          if (failedRead == 0) {
            assertSuccess(response);
            Assertions.assertEquals(Command.AUTH_SAFE, Command.getAuth());
          } else {
            assertError(response, MonoidException.CODE_UNAUTHORIZED);
            Assertions.assertEquals(0, Command.getAuth());
          }
        }

        Assertions.assertEquals(1, calls[0]);
        Assertions.assertEquals(failedRead == 0 ? 3 : failedRead, calls[1]);
        field.set(MonoidApplet.safe, original);
      }
    }
  }

  @Test
  public void authorizationIsRereadBeforeReturningOrGrantingPermissions() throws Exception {
    initializePINs();
    short[] auth = authorization();

    for (String name : new String[] {
      "clearedAuthorization",
      "accessAuthorization",
      "safeAuthorization",
      "accessPermission",
    }) {
      Field field = Command.class.getDeclaredField(name);
      field.setAccessible(true);
      LibSecurity.Condition original = (LibSecurity.Condition) field.get(null);
      short expected = name.equals("clearedAuthorization")
        ? 0
        : name.equals("safeAuthorization") ? Command.AUTH_SAFE : Command.AUTH_ACCESS;

      for (int failedRead = 0; failedRead <= 3; failedRead++) {
        final int failure = failedRead;
        int[] calls = new int[1];
        auth[0] = expected;
        auth[1] = expected == 0 ? 0 : (short) ~expected;
        field.set(
          null,
          (LibSecurity.Condition) () -> {
            calls[0]++;

            if (calls[0] == failure) {
              auth[1] ^= 1;
            }

            return original.check();
          }
        );
        Executable operation = () ->
          Assertions.assertEquals(
            expected,
            name.equals("accessPermission") ? Command.requireAuth() : Command.getAuth()
          );

        if (failedRead == 0) {
          Assertions.assertDoesNotThrow(operation);
        } else {
          assertException(operation, MonoidException.CODE_UNAUTHORIZED);
        }

        Assertions.assertEquals(failedRead == 0 ? 3 : failedRead, calls[0]);
      }

      field.set(null, original);
    }
  }

  @Test
  public void reinstallWithExistingSafeRequiresItsPINBeforeAccessInitialization() {
    initializePINs();
    byte[] safeId = MonoidApplet.safe.getId().clone();
    Assertions.assertTrue(simulator.selectApplet(MONOID_SAFE_AID));
    simulator.deleteApplet(MONOID_AID);
    resetAppletState();
    // jCardSim deletes the instance but retains its loaded applet class.
    simulator.createApplet(MONOID_AID, new byte[0], (short) 0, (byte) 0);
    selectMonoid();

    Assertions.assertArrayEquals(safeId, MonoidApplet.safe.getId());
    Assertions.assertEquals(SAFE_FALSE, MonoidApplet.getPINSetResult(SAFE_TRUE));
    Assertions.assertTrue(MonoidApplet.safe.isPINSet());
    assertError(setPIN(NEW_PIN, false), MonoidException.CODE_UNAUTHORIZED);
    assertException(() -> MonoidApplet.updatePIN(NEW_PIN), MonoidException.CODE_UNAUTHORIZED);
    Assertions.assertEquals(SAFE_FALSE, MonoidApplet.getPINSetResult(SAFE_TRUE));

    assertSuccess(authenticate(PIN, true));
    assertSuccess(setPIN(NEW_PIN, false));
    assertPINs(NEW_PIN, PIN);
  }

  private void resetAppletState() {
    // Separate simulator instances share Java static fields within the test JVM.
    MonoidApplet.version = 0;
    MonoidApplet.safe = null;
    MonoidApplet.safePIN = null;
    MonoidApplet.keystore = null;
  }

  private void selectMonoid() {
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    assertSuccess(transmit(0x20, new byte[] { (byte) 0xA0 }));
  }

  private void assertDamagedPINStateDenied() {
    for (short conservative : new short[] { SAFE_FALSE, SAFE_TRUE }) {
      assertException(
        () -> MonoidApplet.getPINSetResult(conservative),
        MonoidException.CODE_UNAUTHORIZED
      );
    }

    assertError(transmit(0x20, new byte[] { (byte) 0xA0 }), MonoidException.CODE_UNAUTHORIZED);
    assertError(authenticate(PIN, false), MonoidException.CODE_UNAUTHORIZED);
    assertError(setPIN(NEW_PIN, false), MonoidException.CODE_UNAUTHORIZED);
    assertError(setPIN(NEW_PIN, true), MonoidException.CODE_UNAUTHORIZED);
    assertException(() -> MonoidApplet.updatePIN(NEW_PIN), MonoidException.CODE_UNAUTHORIZED);
    assertException(() -> MonoidApplet.updateSafePIN(NEW_PIN), MonoidException.CODE_UNAUTHORIZED);
  }

  private void resetAndSelect() {
    simulator.reset();
    selectMonoid();
  }

  private void initializePINs() {
    assertSuccess(setPIN(PIN, true));
  }

  private void assertPINs(byte[] accessPIN, byte[] safePIN) {
    resetAndSelect();
    assertSuccess(authenticate(accessPIN, false));
    assertSuccess(authenticate(safePIN, true));
  }

  private void assertUnknownPermissionsDenied() {
    for (short invalid : new short[] { 0, 1, -1 }) {
      assertException(() -> Command.requireAuth(invalid), MonoidException.CODE_ACCESS_DENIED);
    }
  }

  private short[] authorization() throws Exception {
    Field field = Command.class.getDeclaredField("auth");
    field.setAccessible(true);
    return (short[]) field.get(null);
  }

  private ResponseAPDU setPIN(byte[] pin, boolean safePIN) {
    return transmit(0x22, pinRequest(pin, safePIN));
  }

  private ResponseAPDU authenticate(byte[] pin, boolean safePIN) {
    return transmit(0x21, pinRequest(pin, safePIN));
  }

  private byte[] pinRequest(byte[] pin, boolean safePIN) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (safePIN ? 2 : 1));
    writer.text(Text.pin);
    writer.text(pin);

    if (safePIN) {
      writer.text(Text.safe);
      writer.bool(true);
    }

    return writer.getDataBuffer();
  }

  private ResponseAPDU transmit(int instruction, byte[] request) {
    return simulator.transmitCommand(new CommandAPDU(0, instruction, 0, 0, request));
  }

  private void assertSuccess(ResponseAPDU response) {
    Assertions.assertEquals(0x9000, response.getSW());
    CBORBufferReader reader = new CBORBufferReader(response.getData());
    reader.map();

    if (reader.key(Text.error)) {
      reader.map();
      Assertions.fail(new String(reader.requireKey(Text.code).text(), StandardCharsets.US_ASCII));
    }
  }

  private CBORBufferReader assertError(ResponseAPDU response, byte[] code) {
    Assertions.assertEquals(0x9000, response.getSW());
    CBORBufferReader reader = new CBORBufferReader(response.getData());
    reader.map();
    reader.requireKey(Text.error).map();
    Assertions.assertArrayEquals(code, reader.requireKey(Text.code).text());
    return reader;
  }

  private void assertException(Executable operation, byte[] code) {
    MonoidException exception = Assertions.assertThrows(MonoidException.class, operation);
    Assertions.assertArrayEquals(code, exception.code);
  }
}
