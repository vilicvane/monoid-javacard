package monoidsafe;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import javacard.framework.AID;
import javacard.framework.OwnerPIN;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tests.AppletTest;
import tests.SafeCallerApplet;
import tests.ShareableSimulatorRuntime;

public class MonoidSafeAuthenticationTest {

  private static final AID SAFE_AID = AIDUtil.create("f06d6f6e6f696400010000");
  private static final AID CALLER_AID = AIDUtil.create("f06d6f6e6f696401010001");
  private static final AID OTHER_CALLER_AID = AIDUtil.create("f06d6f6e6f696401010002");
  private static final AID UNRELATED_AID = AIDUtil.create("f070726f626500000001");

  private static final byte[] PIN = "314159".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] NEW_PIN = "271828".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] WRONG_PIN = "000000".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] DATA = { (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF };

  private CardSimulator simulator;
  private MonoidSafeApplet safe;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    ShareableSimulatorRuntime runtime = new ShareableSimulatorRuntime();
    simulator = new CardSimulator(runtime);
    simulator.installApplet(SAFE_AID, MonoidSafeApplet.class);
    simulator.installApplet(CALLER_AID, SafeCallerApplet.class);
    simulator.installApplet(OTHER_CALLER_AID, SafeCallerApplet.class);
    safe = (MonoidSafeApplet) runtime.lookupApplet(SAFE_AID).getApplet();

    // Both callers already hold their interface when A later authenticates.
    select(OTHER_CALLER_AID);
    assertSuccess(transmit(SafeCallerApplet.GET_SHAREABLE));
    select(CALLER_AID);
    assertSuccess(transmit(SafeCallerApplet.GET_SHAREABLE));
  }

  @Test
  public void onlyPINInitializationIsAllowedBeforePINIsSet() {
    assertBoolean(transmit(SafeCallerApplet.IS_PIN_SET), false);
    assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), false);
    assertDenied(transmit(SafeCallerApplet.LIST));
    assertDenied(transmit(SafeCallerApplet.GET));
    assertDenied(transmit(SafeCallerApplet.CREATE, DATA));
    assertBoolean(transmit(SafeCallerApplet.CHECK_PIN, PIN), false);
    assertData(transmit(SafeCallerApplet.GET_PIN_TRIES), new byte[] { 5 });

    assertSuccess(transmit(SafeCallerApplet.UPDATE_PIN, PIN));
    assertBoolean(transmit(SafeCallerApplet.IS_PIN_SET), true);
    assertDenied(transmit(SafeCallerApplet.LIST));
    assertDenied(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));
    authenticate(PIN);
    assertData(transmit(SafeCallerApplet.LIST), new byte[] { 0, 0 });
  }

  @Test
  public void anotherCallerCannotUseAuthenticatedStorageOrForwardedItems() {
    initializeItem();
    // Shareable references can be forwarded; possession alone must not authorize B.
    select(OTHER_CALLER_AID);
    assertSuccess(transmit(SafeCallerApplet.BORROW_ITEM, AppletTest.aidBytes(CALLER_AID)));

    assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), false);
    assertDenied(transmit(SafeCallerApplet.LIST));
    assertDenied(transmit(SafeCallerApplet.GET));
    assertDenied(transmit(SafeCallerApplet.CREATE, DATA));
    assertDenied(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));

    for (byte instruction : new byte[] {
      SafeCallerApplet.GET_INDEX,
      SafeCallerApplet.GET_ALIAS,
      SafeCallerApplet.GET_DATA,
      SafeCallerApplet.SET_ALIAS,
      SafeCallerApplet.SET_DATA,
      SafeCallerApplet.REMOVE,
    }) {
      assertDenied(transmit(instruction, DATA));
    }

    select(CALLER_AID);
    assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), true);
    assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
  }

  @Test
  public void callersKeepIndependentAuthorizationAcrossSelections() {
    initializeBothCallers();

    for (int iteration = 0; iteration < 3; iteration++) {
      for (AID callerAID : new AID[] { CALLER_AID, OTHER_CALLER_AID }) {
        select(callerAID);
        assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), true);
        assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
      }
    }
  }

  @Test
  public void obtainingAnInterfaceAgainPreservesTheSessionAndItsItems() {
    initializeBothCallers();

    for (AID callerAID : new AID[] { OTHER_CALLER_AID, CALLER_AID }) {
      select(callerAID);
      assertBoolean(transmit(SafeCallerApplet.GET_SHAREABLE), true);
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), true);
      assertData(transmit(SafeCallerApplet.GET_DATA), DATA);

      select(callerAID == CALLER_AID ? OTHER_CALLER_AID : CALLER_AID);
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), true);
      assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
    }
  }

  @Test
  public void itemsRemainBoundToTheirSessionAfterFailedAuthenticationAndReacquisition() {
    initializeItem();
    assertBoolean(transmit(SafeCallerApplet.CHECK_PIN, WRONG_PIN), false);
    assertBoolean(transmit(SafeCallerApplet.GET_SHAREABLE), false);
    authenticate(PIN);

    assertDenied(transmit(SafeCallerApplet.GET_DATA));
    assertDenied(transmit(SafeCallerApplet.SET_DATA, NEW_PIN));
    assertDenied(transmit(SafeCallerApplet.REMOVE));

    assertBoolean(transmit(SafeCallerApplet.GET), true);
    assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
  }

  @Test
  public void PINUpdatesRevokeEveryCallerAndRequireTheNewPIN() {
    initializeBothCallers();
    assertSuccess(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));

    for (AID callerAID : new AID[] { CALLER_AID, OTHER_CALLER_AID }) {
      select(callerAID);
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), false);
      assertDenied(transmit(SafeCallerApplet.GET_DATA));
      assertBoolean(transmit(SafeCallerApplet.CHECK_PIN, PIN), false);
      authenticate(NEW_PIN);
      assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
    }
  }

  @Test
  public void failingPINUpdatesRevokeEveryCallerAndPreserveThePIN() {
    initializeBothCallers();
    byte[] oversizedPIN = new byte[MonoidSafeApplet.MAX_PIN_LENGTH + 1];
    Assertions.assertNotEquals(0x9000, transmit(SafeCallerApplet.UPDATE_PIN, oversizedPIN).getSW());

    for (AID callerAID : new AID[] { CALLER_AID, OTHER_CALLER_AID }) {
      select(callerAID);
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), false);
      assertDenied(transmit(SafeCallerApplet.GET_DATA));
      authenticate(PIN);
      assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
    }
  }

  @Test
  public void resetRevokesEveryCallerEvenWithCachedInterfaces() {
    initializeBothCallers();
    simulator.reset();

    for (AID callerAID : new AID[] { CALLER_AID, OTHER_CALLER_AID }) {
      select(callerAID);
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), false);
      assertDenied(transmit(SafeCallerApplet.GET_DATA));
      assertDenied(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));
      authenticate(PIN);
      assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
    }
  }

  @Test
  public void failedPINChecksOnlyRevokeTheSameCallerAndConsumeOneAttempt() {
    initializeBothCallers();

    for (AID callerAID : new AID[] { CALLER_AID, OTHER_CALLER_AID }) {
      select(CALLER_AID);
      authenticate(PIN);
      select(OTHER_CALLER_AID);
      authenticate(PIN);
      select(callerAID);
      assertBoolean(transmit(SafeCallerApplet.CHECK_PIN, WRONG_PIN), false);
      assertData(transmit(SafeCallerApplet.GET_PIN_TRIES), new byte[] { 4 });
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), false);
      assertDenied(transmit(SafeCallerApplet.GET_DATA));

      select(callerAID == CALLER_AID ? OTHER_CALLER_AID : CALLER_AID);
      assertData(transmit(SafeCallerApplet.GET_PIN_TRIES), new byte[] { 4 });
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), true);
      assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
    }
  }

  @Test
  public void throwingPINChecksOnlyRevokeTheSameCaller() {
    initializeBothCallers();

    for (AID callerAID : new AID[] { CALLER_AID, OTHER_CALLER_AID }) {
      select(CALLER_AID);
      authenticate(PIN);
      select(OTHER_CALLER_AID);
      authenticate(PIN);
      select(callerAID);
      Assertions.assertNotEquals(0x9000, transmit(SafeCallerApplet.CHECK_NULL_PIN).getSW());
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), false);
      assertDenied(transmit(SafeCallerApplet.GET_DATA));

      select(callerAID == CALLER_AID ? OTHER_CALLER_AID : CALLER_AID);
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), true);
      assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
    }
  }

  @Test
  public void exhaustingSharedPINAttemptsRevokesEveryCaller() {
    initializeBothCallers();
    select(OTHER_CALLER_AID);

    for (byte remaining = 4; remaining >= 0; remaining--) {
      assertBoolean(transmit(SafeCallerApplet.CHECK_PIN, WRONG_PIN), false);
      assertData(transmit(SafeCallerApplet.GET_PIN_TRIES), new byte[] { remaining });
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), false);
      assertDenied(transmit(SafeCallerApplet.GET_DATA));

      select(CALLER_AID);
      assertData(transmit(SafeCallerApplet.GET_PIN_TRIES), new byte[] { remaining });
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), remaining != 0);

      if (remaining != 0) {
        assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
      } else {
        assertDenied(transmit(SafeCallerApplet.GET_DATA));
      }

      select(OTHER_CALLER_AID);
    }

    for (AID callerAID : new AID[] { CALLER_AID, OTHER_CALLER_AID }) {
      select(callerAID);
      assertBoolean(transmit(SafeCallerApplet.CHECK_PIN, PIN), false);
      assertData(transmit(SafeCallerApplet.GET_PIN_TRIES), new byte[] { 0 });
      assertDenied(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));
    }
  }

  @Test
  public void throwingOnTheLastPINAttemptRevokesEveryCaller() {
    initializeBothCallers();
    select(OTHER_CALLER_AID);

    for (byte remaining = 4; remaining > 0; remaining--) {
      assertBoolean(transmit(SafeCallerApplet.CHECK_PIN, WRONG_PIN), false);
      assertData(transmit(SafeCallerApplet.GET_PIN_TRIES), new byte[] { remaining });
    }

    Assertions.assertNotEquals(0x9000, transmit(SafeCallerApplet.CHECK_NULL_PIN).getSW());

    for (AID callerAID : new AID[] { CALLER_AID, OTHER_CALLER_AID }) {
      select(callerAID);
      assertData(transmit(SafeCallerApplet.GET_PIN_TRIES), new byte[] { 0 });
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), false);
      assertDenied(transmit(SafeCallerApplet.GET_DATA));
      assertDenied(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));
    }
  }

  @Test
  public void reinstallingAfterResetDoesNotInheritAuthorization() {
    initializeBothCallers();
    select(OTHER_CALLER_AID);
    simulator.deleteApplet(CALLER_AID);

    // An explicit card reset revokes every caller before the new instance is installed.
    simulator.reset();
    createCallerWithNewAIDObject();
    select(OTHER_CALLER_AID);
    assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), false);
    assertDenied(transmit(SafeCallerApplet.GET_DATA));

    select(CALLER_AID);
    assertBoolean(transmit(SafeCallerApplet.GET_SHAREABLE), false);
    assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), false);
    assertDenied(transmit(SafeCallerApplet.GET));
    assertDenied(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));
    authenticate(PIN);
    assertBoolean(transmit(SafeCallerApplet.GET), true);
    assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
  }

  @Test
  public void reinstallingWithANewAIDObjectPreservesOtherCallersWithoutReset() {
    initializeBothCallers();
    select(OTHER_CALLER_AID);
    simulator.deleteApplet(CALLER_AID);
    createCallerWithNewAIDObject();

    select(OTHER_CALLER_AID);
    assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), true);
    assertData(transmit(SafeCallerApplet.GET_DATA), DATA);

    // SELECT uses the same AID bytes; the installed instance owns a different AID object.
    select(CALLER_AID);
    assertBoolean(transmit(SafeCallerApplet.GET_SHAREABLE), false);
    assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), false);
    assertDenied(transmit(SafeCallerApplet.GET));
    assertDenied(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));

    select(OTHER_CALLER_AID);
    assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), true);
    assertData(transmit(SafeCallerApplet.GET_DATA), DATA);

    select(CALLER_AID);
    authenticate(PIN);
    assertBoolean(transmit(SafeCallerApplet.GET), true);
    assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
  }

  @Test
  public void reinstallingTheSameAIDCannotUseAnotherCallersCachedInterface() {
    initializeItem();
    select(OTHER_CALLER_AID);
    simulator.deleteApplet(CALLER_AID);
    createCallerWithNewAIDObject();

    // B can forward its own cached SIO without reacquiring one or knowing the PIN.
    select(CALLER_AID);
    assertSuccess(transmit(SafeCallerApplet.BORROW_SAFE, AppletTest.aidBytes(OTHER_CALLER_AID)));
    assertDenied(transmit(SafeCallerApplet.IS_PIN_VALIDATED));
    assertDenied(transmit(SafeCallerApplet.LIST));
    assertDenied(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));
  }

  @Test
  public void reinstallingTheSameAIDCannotReuseAnOldItemAfterAPINChange() {
    initializeItem();
    select(OTHER_CALLER_AID);
    authenticate(PIN);
    assertBoolean(transmit(SafeCallerApplet.GET), true);

    select(CALLER_AID);
    authenticate(PIN);
    assertSuccess(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));
    authenticate(NEW_PIN);
    select(OTHER_CALLER_AID);
    simulator.deleteApplet(CALLER_AID);
    createCallerWithNewAIDObject();

    select(CALLER_AID);
    assertSuccess(transmit(SafeCallerApplet.BORROW_ITEM, AppletTest.aidBytes(OTHER_CALLER_AID)));
    assertDenied(transmit(SafeCallerApplet.GET_DATA));
    assertDenied(transmit(SafeCallerApplet.SET_DATA, DATA));
    assertDenied(transmit(SafeCallerApplet.REMOVE));
  }

  @Test
  public void rejectsEverySingleBitChangeInAuthorization() throws Exception {
    initializeItem();
    short[] auth = authorization();

    for (short[] valid : new short[][] { new short[2], auth.clone() }) {
      for (int word = 0; word < auth.length; word++) {
        for (int bit = 0; bit < 16; bit++) {
          System.arraycopy(valid, 0, auth, 0, auth.length);
          auth[word] ^= (short) (1 << bit);
          assertDenied(transmit(SafeCallerApplet.IS_PIN_VALIDATED));
          assertDenied(transmit(SafeCallerApplet.GET_DATA));
          assertDenied(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));
        }
      }
    }
  }

  @Test
  public void rejectsInvalidAuthorizationCodesEvenWithMatchingComplements() throws Exception {
    initializeItem();
    short[] auth = authorization();

    for (short invalid : new short[] { 0, 1, -1, (short) 0xA501 }) {
      auth[0] = invalid;
      auth[1] = (short) ~invalid;
      assertDenied(transmit(SafeCallerApplet.IS_PIN_VALIDATED));
      assertDenied(transmit(SafeCallerApplet.GET_DATA));
    }
  }

  @Test
  public void resettingTheNativePINFlagPreservesIssuedSessionAuthorization() throws Exception {
    initializeBothCallers();
    OwnerPIN pin = (OwnerPIN) field("pin").get(safe);
    pin.reset();

    // Native validation is checked when issuing a grant, not on subsequent session access.
    for (AID callerAID : new AID[] { CALLER_AID, OTHER_CALLER_AID }) {
      select(callerAID);
      assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), true);
      assertData(transmit(SafeCallerApplet.GET_DATA), DATA);
    }
  }

  @Test
  public void damagedPINStateCannotBypassInitializationOrAuthorization() throws Exception {
    Field state = field("pinState");
    Field inverse = field("pinStateInverse");

    for (boolean initialized : new boolean[] { false, true }) {
      if (initialized) {
        initializeItem();
      }

      short validState = state.getShort(safe);
      short validInverse = inverse.getShort(safe);

      for (Field target : new Field[] { state, inverse }) {
        for (int bit = 0; bit < 16; bit++) {
          state.setShort(safe, validState);
          inverse.setShort(safe, validInverse);
          target.setShort(safe, (short) (target.getShort(safe) ^ (1 << bit)));
          assertDenied(transmit(SafeCallerApplet.IS_PIN_SET));
          assertDenied(transmit(SafeCallerApplet.LIST));
          assertDenied(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));
        }
      }

      for (short invalid : new short[] { 0, 1, -1 }) {
        state.setShort(safe, invalid);
        inverse.setShort(safe, (short) ~invalid);
        assertDenied(transmit(SafeCallerApplet.IS_PIN_SET));
        assertDenied(transmit(SafeCallerApplet.UPDATE_PIN, NEW_PIN));
      }

      state.setShort(safe, validState);
      inverse.setShort(safe, validInverse);
    }
  }

  @Test
  public void unrelatedAIDCannotAcquireTheSafeInterface() {
    simulator.installApplet(UNRELATED_AID, SafeCallerApplet.class);
    select(UNRELATED_AID);
    assertDenied(transmit(SafeCallerApplet.GET_SHAREABLE));
  }

  private void initializeItem() {
    assertSuccess(transmit(SafeCallerApplet.UPDATE_PIN, PIN));
    authenticate(PIN);
    assertBoolean(transmit(SafeCallerApplet.CREATE, DATA), true);
  }

  private void initializeBothCallers() {
    initializeItem();
    select(OTHER_CALLER_AID);
    authenticate(PIN);
    assertBoolean(transmit(SafeCallerApplet.GET), true);
    select(CALLER_AID);
  }

  private void createCallerWithNewAIDObject() {
    byte[] bytes = AppletTest.aidBytes(CALLER_AID);
    AID replacementAID = new AID(bytes, (short) 0, (byte) bytes.length);
    Assertions.assertEquals(CALLER_AID, replacementAID);
    Assertions.assertNotSame(CALLER_AID, replacementAID);

    // jCardSim stores this exact object and retains the loaded class after instance deletion.
    simulator.createApplet(replacementAID, new byte[0], (short) 0, (byte) 0);
  }

  private void authenticate(byte[] pin) {
    assertBoolean(transmit(SafeCallerApplet.CHECK_PIN, pin), true);
    assertBoolean(transmit(SafeCallerApplet.IS_PIN_VALIDATED), true);
  }

  private void select(AID aid) {
    Assertions.assertTrue(simulator.selectApplet(aid));
  }

  private Field field(String name) throws Exception {
    // Only fault injection uses reflection; normal calls use APDUs and shareable interfaces.
    Field field = MonoidSafeApplet.class.getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private short[] authorization() throws Exception {
    Object[] sessions = (Object[]) field("sessions").get(safe);
    SafeSession session = (SafeSession) sessions[0];
    Field field = SafeSession.class.getDeclaredField("auth");
    field.setAccessible(true);
    return (short[]) field.get(session);
  }

  private ResponseAPDU transmit(byte instruction) {
    return transmit(instruction, new byte[0]);
  }

  private ResponseAPDU transmit(byte instruction, byte[] data) {
    return simulator.transmitCommand(new CommandAPDU(0, instruction, 0, 0, data));
  }

  private void assertSuccess(ResponseAPDU response) {
    Assertions.assertEquals(0x9000, response.getSW());
  }

  private void assertDenied(ResponseAPDU response) {
    Assertions.assertEquals(0x6982, response.getSW());
  }

  private void assertBoolean(ResponseAPDU response, boolean value) {
    assertData(response, new byte[] { value ? (byte) 1 : 0 });
  }

  private void assertData(ResponseAPDU response, byte[] data) {
    assertSuccess(response);
    Assertions.assertArrayEquals(data, response.getData());
  }
}
