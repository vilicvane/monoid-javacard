package monoid;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoidsafe.MonoidSafeApplet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import tests.ShareableSimulatorRuntime;

public class CommandAuthenticationTest {

  private static final AID MONOID_SAFE_AID = AIDUtil.create("f06d6f6e6f696400010000");
  private static final AID MONOID_AID = AIDUtil.create("f06d6f6e6f696401010000");

  private static final byte[] PIN = "314159".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] NEW_PIN = "271828".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] WRONG_PIN = "000000".getBytes(StandardCharsets.US_ASCII);

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    resetAppletState();

    simulator = new CardSimulator(new ShareableSimulatorRuntime());
    simulator.installApplet(MONOID_SAFE_AID, MonoidSafeApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    selectMonoid();
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(MONOID_AID);
    simulator.deleteApplet(MONOID_SAFE_AID);
    resetAppletState();
  }

  @Test
  public void initializesBothPINsFromClearedAuthorization() throws Exception {
    Assertions.assertArrayEquals(new short[2], authorization());
    Assertions.assertEquals(0, Command.getAuth());
    assertError(setPIN(PIN, false), MonoidException.CODE_SAFE_PIN_NOT_SET);
    assertException(() -> MonoidApplet.updatePIN(PIN), MonoidException.CODE_SAFE_PIN_NOT_SET);
    Assertions.assertFalse(MonoidApplet.pinSet);
    Assertions.assertFalse(MonoidApplet.safe.isPINSet());

    initializePINs();
    Assertions.assertTrue(MonoidApplet.pinSet);
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
      Assertions.assertFalse(MonoidApplet.pinSet);
      Assertions.assertFalse(MonoidApplet.safe.isPINSet());
    }
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
    Assertions.assertFalse(MonoidApplet.pinSet);
    Assertions.assertTrue(MonoidApplet.safe.isPINSet());
    assertError(setPIN(NEW_PIN, false), MonoidException.CODE_UNAUTHORIZED);
    assertException(() -> MonoidApplet.updatePIN(NEW_PIN), MonoidException.CODE_UNAUTHORIZED);
    Assertions.assertFalse(MonoidApplet.pinSet);

    assertSuccess(authenticate(PIN, true));
    assertSuccess(setPIN(NEW_PIN, false));
    assertPINs(NEW_PIN, PIN);
  }

  private void resetAppletState() {
    // Separate simulator instances share Java static fields within the test JVM.
    MonoidApplet.version = 0;
    MonoidApplet.pinSet = false;
    MonoidApplet.safe = null;
    MonoidApplet.safePIN = null;
    MonoidApplet.keystore = null;
  }

  private void selectMonoid() {
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    assertSuccess(transmit(0x20, new byte[] { (byte) 0xA0 }));
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
