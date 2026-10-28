package monoid;

import static monoid.Constants.SAFE_FALSE;
import static monoid.Constants.SAFE_TRUE;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import javacard.framework.AID;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Shareable;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoididentity.IdentityShareable;
import monoididentity.MonoidIdentityApplet;
import monoidlib.CBORBufferReader;
import monoidlib.CBORBufferWriter;
import monoidlib.LibSecurity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

public class CommandAuthenticationTest {

  private static final AID MONOID_IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_IDENTITY_AID}}"
    "f06d6f6e6f69640001"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );

  private static final byte[] PIN = "314159".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] NEW_PIN = "271828".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] WRONG_PIN = "000000".getBytes(StandardCharsets.US_ASCII);

  private CardSimulator simulator;
  private IdentityRuntime runtime;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    resetAppletState();

    runtime = new IdentityRuntime();
    simulator = new CardSimulator(runtime);
    simulator.installApplet(MONOID_IDENTITY_AID, MonoidIdentityApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    selectMonoid();
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(MONOID_AID);
    simulator.deleteApplet(MONOID_IDENTITY_AID);
    resetAppletState();
  }

  @Test
  public void initializesBothPINsFromClearedAuthorization() throws Exception {
    Assertions.assertArrayEquals(new short[2], authorization());
    Assertions.assertEquals(0, Command.getAuth());
    requireError(setPIN(PIN, false), MonoidException.CODE_SECRET_PIN_NOT_SET);
    assertException(() -> MonoidApplet.updatePIN(PIN), MonoidException.CODE_SECRET_PIN_NOT_SET);
    Assertions.assertEquals(SAFE_FALSE, MonoidApplet.getPINSetResult(SAFE_TRUE));
    Assertions.assertFalse(MonoidApplet.safe.isPINSet());

    initializePINs();
    Assertions.assertEquals(SAFE_TRUE, MonoidApplet.getPINSetResult(SAFE_FALSE));
    Assertions.assertTrue(MonoidApplet.safe.isPINSet());
    Assertions.assertEquals(0, Command.getAuth());
    assertPINs(PIN, PIN);
  }

  @Test
  public void supports32BytePINsThroughInitializationUpdatesAndReset() {
    byte[] longPIN = "01234567890123456789012345678901".getBytes(StandardCharsets.US_ASCII);
    byte[] wrongPIN = longPIN.clone();
    wrongPIN[31] ^= 1;

    assertSuccess(setPIN(longPIN, true));
    assertPINs(longPIN, longPIN);

    for (boolean secretPIN : new boolean[] { false, true }) {
      resetAndSelect();
      requireError(authenticate(wrongPIN, secretPIN), MonoidException.CODE_INVALID_PIN);
      assertSuccess(authenticate(longPIN, secretPIN));
    }

    assertSuccess(setPIN(NEW_PIN, false));
    assertSuccess(setPIN(NEW_PIN, true));
    assertPINs(NEW_PIN, NEW_PIN);

    assertSuccess(setPIN(longPIN, false));
    assertSuccess(setPIN(longPIN, true));
    assertPINs(longPIN, longPIN);
  }

  @Test
  public void accessAuthorizationCannotChangeEitherPIN() {
    initializePINs();
    assertSuccess(authenticate(PIN, false));
    Assertions.assertEquals(Command.AUTH_ACCESS, Command.requireAuth(Command.AUTH_ACCESS));
    assertException(
      () -> Command.requireAuth(Command.AUTH_SECRET),
      MonoidException.CODE_ACCESS_DENIED
    );
    assertUnknownPermissionsDenied();

    requireError(setPIN(NEW_PIN, false), MonoidException.CODE_ACCESS_DENIED);
    requireError(setPIN(NEW_PIN, true), MonoidException.CODE_ACCESS_DENIED);
    assertPINs(PIN, PIN);
  }

  @Test
  public void secretAuthorizationCanChangeBothPINs() {
    initializePINs();
    assertSuccess(authenticate(PIN, true));
    Assertions.assertEquals(Command.AUTH_SECRET, Command.requireAuth(Command.AUTH_ACCESS));
    Assertions.assertEquals(Command.AUTH_SECRET, Command.requireAuth(Command.AUTH_SECRET));
    assertUnknownPermissionsDenied();

    assertSuccess(setPIN(NEW_PIN, false));
    assertSuccess(setPIN(NEW_PIN, true));
    assertPINs(NEW_PIN, NEW_PIN);
  }

  @Test
  public void directPINUpdatesRequireUserSecretAuthorization() {
    initializePINs();

    assertException(MonoidApplet.safe::checkAccess, MonoidException.CODE_UNAUTHORIZED);
    assertException(() -> MonoidApplet.updatePIN(NEW_PIN), MonoidException.CODE_UNAUTHORIZED);
    assertException(() -> MonoidApplet.updateSecretPIN(NEW_PIN), MonoidException.CODE_UNAUTHORIZED);

    assertSuccess(authenticate(PIN, false));
    MonoidApplet.safe.checkAccess();
    assertException(() -> MonoidApplet.updatePIN(NEW_PIN), MonoidException.CODE_ACCESS_DENIED);
    assertException(
      () -> MonoidApplet.updateSecretPIN(NEW_PIN),
      MonoidException.CODE_ACCESS_DENIED
    );
    assertPINs(PIN, PIN);
  }

  @Test
  public void PINUpdatesRecheckAuthorizationAfterEntry() throws Exception {
    initializePINs();
    short[] auth = authorization();

    for (boolean secretPIN : new boolean[] { false, true }) {
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
            if (secretPIN) {
              MonoidApplet.updateSecretPIN(NEW_PIN);
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

    for (short state : new short[] { 0, Command.AUTH_ACCESS, Command.AUTH_SECRET }) {
      resetAndSelect();

      if (state != 0) {
        assertSuccess(authenticate(PIN, state == Command.AUTH_SECRET));
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
            () -> Command.requireAuth(Command.AUTH_SECRET),
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
      requireError(setPIN(PIN, true), MonoidException.CODE_UNAUTHORIZED);
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
        Assertions.assertTrue(simulator.selectApplet(MONOID_IDENTITY_AID));
      }

      selectMonoid();
      Assertions.assertArrayEquals(new short[2], authorization());
      assertException(
        () -> Command.requireAuth(Command.AUTH_ACCESS),
        MonoidException.CODE_UNAUTHORIZED
      );
      assertException(MonoidApplet.safe::checkAccess, MonoidException.CODE_UNAUTHORIZED);
      requireError(setPIN(NEW_PIN, false), MonoidException.CODE_UNAUTHORIZED);
    }
  }

  @Test
  public void incorrectPINConsumesOneAttemptAndPreservesExistingAuthorization() {
    initializePINs();

    for (boolean secretPIN : new boolean[] { false, true }) {
      assertSuccess(authenticate(PIN, true));

      for (short remaining = 4; remaining >= 3; remaining--) {
        CBORBufferReader reader = requireError(
          authenticate(WRONG_PIN, secretPIN),
          MonoidException.CODE_INVALID_PIN
        );
        Assertions.assertEquals(remaining, reader.requireKey(Text.tries).integer());
        Assertions.assertEquals(
          remaining,
          secretPIN
            ? MonoidApplet.safe.getPINTriesRemaining()
            : MonoidApplet.pin.getTriesRemaining()
        );
        Assertions.assertEquals(Command.AUTH_SECRET, Command.getAuth());
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
        requireError(response, MonoidException.CODE_UNAUTHORIZED);
        Assertions.assertEquals(0, Command.getAuth());
      }
    }
  }

  @Test
  public void accessAuthorizationOpensStorageWithoutGrantingSecretAuthorization() {
    initializePINs();
    resetAndSelect();
    Safe safe = MonoidApplet.safe;
    assertSuccess(authenticate(PIN, false));

    for (int operation = 0; operation < 2; operation++) {
      safe.checkAccess();
      Assertions.assertEquals(0, safe.list((short) 0).getCount());
      Assertions.assertFalse(safe.isPINValidated());
      Assertions.assertEquals(5, safe.getPINTriesRemaining());
      Assertions.assertEquals(Command.AUTH_ACCESS, Command.getAuth());
    }
  }

  @Test
  public void encodedSecretAuthorizationCannotReplaceIdentityPINVerification() throws Exception {
    initializePINs();
    resetAndSelect();
    short[] auth = authorization();
    auth[0] = Command.AUTH_SECRET;
    auth[1] = (short) ~Command.AUTH_SECRET;
    Assertions.assertFalse(MonoidApplet.safe.isPINValidated());
    requireError(setPIN(NEW_PIN, false), MonoidException.CODE_UNAUTHORIZED);
    requireError(setPIN(NEW_PIN, true), MonoidException.CODE_UNAUTHORIZED);
    assertPINs(PIN, PIN);
  }

  @Test
  public void changingSecretPINRequiresVerificationBeforeFurtherPINChanges() {
    initializePINs();
    assertSuccess(authenticate(PIN, true));
    assertSuccess(setPIN(NEW_PIN, true));
    requireError(setPIN(NEW_PIN, false), MonoidException.CODE_UNAUTHORIZED);
    assertSuccess(authenticate(NEW_PIN, true));
    assertSuccess(setPIN(NEW_PIN, false));
    assertPINs(NEW_PIN, NEW_PIN);
  }

  @Test
  public void safeAccessRequiresInitializedAndUnblockedPIN() throws Exception {
    short[] auth = authorization();
    auth[0] = Command.AUTH_ACCESS;
    auth[1] = (short) ~Command.AUTH_ACCESS;
    assertException(MonoidApplet.safe::checkAccess, MonoidException.CODE_SECRET_PIN_NOT_SET);

    resetAndSelect();
    initializePINs();
    assertSuccess(authenticate(PIN, false));

    for (int attempt = 0; attempt < monoididentity.SecretPIN.PIN_TRY_LIMIT; attempt++) {
      Assertions.assertFalse(MonoidApplet.safe.checkPIN(WRONG_PIN));
    }

    Assertions.assertEquals(0, MonoidApplet.safe.getPINTriesRemaining());
    assertException(MonoidApplet.safe::checkAccess, MonoidException.CODE_SECRET_PIN_BLOCKED);
    Assertions.assertFalse(MonoidApplet.safe.isPINValidated());
  }

  @Test
  public void safeAccessChecksPINStateConservatively() {
    initializePINs();
    Safe safe = MonoidApplet.safe;

    for (String name : new String[] { "isSecretPINSet", "getSecretPINTriesRemaining" }) {
      boolean blocked = name.equals("getSecretPINTriesRemaining");

      for (int failedRead = 0; failedRead <= 3; failedRead++) {
        resetAndSelect();
        assertSuccess(authenticate(PIN, false));
        runtime.failingMethod = name;
        runtime.failedRead = failedRead;
        runtime.stateReads = 0;

        try {
          if (failedRead == 0) {
            safe.checkAccess();
          } else {
            assertException(
              safe::checkAccess,
              blocked
                ? MonoidException.CODE_SECRET_PIN_BLOCKED
                : MonoidException.CODE_SECRET_PIN_NOT_SET
            );
          }

          Assertions.assertEquals(failedRead == 0 ? 3 : failedRead, runtime.stateReads);
        } finally {
          runtime.failingMethod = null;
        }

        Assertions.assertFalse(safe.isPINValidated());
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
      "secretAuthorization",
      "accessPermission",
    }) {
      Field field = Command.class.getDeclaredField(name);
      field.setAccessible(true);
      LibSecurity.Condition original = (LibSecurity.Condition) field.get(null);
      short expected = name.equals("clearedAuthorization")
        ? 0
        : name.equals("secretAuthorization") ? Command.AUTH_SECRET : Command.AUTH_ACCESS;

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
  public void reinstallClearsAccessPINWhilePreservingIdentitySecretPIN() {
    initializePINs();
    byte[] safeId = MonoidApplet.safe.getId().clone();
    Assertions.assertTrue(simulator.selectApplet(MONOID_IDENTITY_AID));
    simulator.deleteApplet(MONOID_AID);
    resetAppletState();
    // jCardSim deletes the instance but retains its loaded applet class.
    simulator.createApplet(MONOID_AID, new byte[0], (short) 0, (byte) 0);
    selectMonoid();

    Assertions.assertArrayEquals(safeId, MonoidApplet.safe.getId());
    Assertions.assertEquals(SAFE_FALSE, MonoidApplet.getPINSetResult(SAFE_TRUE));
    Assertions.assertTrue(MonoidApplet.safe.isPINSet());
    Assertions.assertFalse(MonoidApplet.safe.isPINValidated());
    Assertions.assertEquals(0, Command.getAuth());
    requireError(authenticate(PIN, false), MonoidException.CODE_PIN_NOT_SET);
    requireError(setPIN(NEW_PIN, false), MonoidException.CODE_UNAUTHORIZED);
    assertSuccess(authenticate(PIN, true));
    assertSuccess(setPIN(NEW_PIN, false));
    assertPINs(NEW_PIN, PIN);
  }

  private void resetAppletState() {
    // Separate simulator instances share Java static fields within the test JVM.
    MonoidApplet.safe = null;
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

    requireError(transmit(0x20, new byte[] { (byte) 0xA0 }), MonoidException.CODE_UNAUTHORIZED);
    requireError(authenticate(PIN, false), MonoidException.CODE_UNAUTHORIZED);
    requireError(setPIN(NEW_PIN, false), MonoidException.CODE_UNAUTHORIZED);
    requireError(setPIN(NEW_PIN, true), MonoidException.CODE_UNAUTHORIZED);
    assertException(() -> MonoidApplet.updatePIN(NEW_PIN), MonoidException.CODE_UNAUTHORIZED);
    assertException(() -> MonoidApplet.updateSecretPIN(NEW_PIN), MonoidException.CODE_UNAUTHORIZED);
  }

  private void resetAndSelect() {
    simulator.reset();
    selectMonoid();
  }

  private void initializePINs() {
    assertSuccess(setPIN(PIN, true));
  }

  private void assertPINs(byte[] accessPIN, byte[] secretPIN) {
    resetAndSelect();
    assertSuccess(authenticate(accessPIN, false));
    assertSuccess(authenticate(secretPIN, true));
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

  private ResponseAPDU setPIN(byte[] pin, boolean secretPIN) {
    return transmit(0x22, pinRequest(pin, secretPIN));
  }

  private ResponseAPDU authenticate(byte[] pin, boolean secretPIN) {
    return transmit(0x21, pinRequest(pin, secretPIN));
  }

  private byte[] pinRequest(byte[] pin, boolean secretPIN) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (secretPIN ? 2 : 1));
    writer.text(Text.pin);
    writer.text(pin);

    if (secretPIN) {
      writer.text(Text.secret);
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

  private CBORBufferReader requireError(ResponseAPDU response, byte[] code) {
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

  private static final class IdentityRuntime extends ShareableSimulatorRuntime {

    private String failingMethod;
    private int failedRead;
    private int stateReads;

    @Override
    public Shareable getSharedObject(AID serverAID, byte parameter) {
      Shareable identity = super.getSharedObject(serverAID, parameter);

      if (!(identity instanceof IdentityShareable)) {
        return identity;
      }

      return (Shareable) Proxy.newProxyInstance(
        IdentityShareable.class.getClassLoader(),
        new Class<?>[] { IdentityShareable.class },
        (proxy, method, arguments) -> {
          if (method.getName().equals(failingMethod) && ++stateReads == failedRead) {
            if (method.getName().equals("isSecretPINSet")) {
              return false;
            }

            return (short) 0;
          }

          try {
            return method.invoke(identity, arguments);
          } catch (InvocationTargetException exception) {
            throw exception.getCause();
          }
        }
      );
    }
  }
}
