package monoid;

import static monoid.TestData.read;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import main.ShareableSimulatorRuntime;
import monoidsafeidentity.MonoidSafeIdentityApplet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

public class SafeAuthenticationTest {

  private static final AID IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_IDENTITY_AID}}"
    "f06d6f6e6f696400010000"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f696402010000"
  );

  private static final byte[] PIN = "314159".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] NEW_PIN = "271828".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] WRONG_PIN = "000000".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] INDEX = { 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
  private static final byte[] DATA = { (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF };

  private CardSimulator simulator;
  private Safe safe;
  private SafeItem item;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    simulator = new CardSimulator(new ShareableSimulatorRuntime());
    simulator.installApplet(IDENTITY_AID, MonoidSafeIdentityApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    safe = new Safe();
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(MONOID_AID);
    simulator.deleteApplet(IDENTITY_AID);
  }

  @Test
  public void onlyPINInitializationIsAllowedBeforePINIsSet() {
    Assertions.assertFalse(safe.isPINSet());
    Assertions.assertFalse(safe.isPINValidated());
    assertDenied(() -> safe.list((short) 0));
    assertDenied(() -> safe.get(INDEX));
    assertDenied(() -> safe.create(INDEX, null, null, new TestData(DATA), false));
    Assertions.assertFalse(checkPIN(PIN));
    Assertions.assertEquals(5, safe.getPINTriesRemaining());

    updatePIN(PIN);
    Assertions.assertTrue(safe.isPINSet());
    assertDenied(() -> safe.list((short) 0));
    assertDenied(() -> updatePIN(NEW_PIN));
    authenticate(PIN);
    Assertions.assertEquals(0, safe.list((short) 0).getCount());
  }

  @Test
  public void PINValidationMustPassEveryReadBeforeGrantingAuthorization() throws Exception {
    initializeItem();

    for (int failedRead = 0; failedRead <= 3; failedRead++) {
      final int failure = failedRead;
      int[] calls = new int[2];
      OwnerPIN observed = new OwnerPIN(Safe.PIN_TRY_LIMIT, Safe.MAX_PIN_LENGTH) {
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
      field("pin").set(safe, observed);

      if (failedRead == 0) {
        Assertions.assertTrue(checkPIN(PIN));
        Assertions.assertArrayEquals(DATA, read(item.getData()));
      } else {
        assertDenied(() -> checkPIN(PIN));
        assertDenied(() -> item.getData());
      }

      Assertions.assertEquals(1, calls[0]);
      Assertions.assertEquals(failedRead == 0 ? 3 : failedRead, calls[1]);
    }
  }

  @Test
  public void PINInitializationRequiresEveryReadToRemainUnset() throws Exception {
    Field validation = field("pinSetValidation");
    LibSecurity.Condition original = (LibSecurity.Condition) validation.get(safe);
    int[] updates = new int[1];
    OwnerPIN observed = new OwnerPIN(Safe.PIN_TRY_LIMIT, Safe.MAX_PIN_LENGTH) {
      @Override
      public void update(byte[] buffer, short offset, byte length) {
        updates[0]++;
        super.update(buffer, offset, length);
      }
    };
    field("pin").set(safe, observed);

    for (int setRead = 1; setRead <= 3; setRead++) {
      final int failure = setRead;
      int[] calls = new int[1];
      validation.set(safe, (LibSecurity.Condition) () -> ++calls[0] == failure || original.check());
      assertDenied(() -> updatePIN(PIN));
      Assertions.assertTrue(calls[0] >= setRead);
      Assertions.assertEquals(0, updates[0]);
      validation.set(safe, original);
      Assertions.assertFalse(safe.isPINSet());
    }

    updatePIN(PIN);
    Assertions.assertEquals(1, updates[0]);
    authenticate(PIN);
  }

  @Test
  public void anyBlockedReadPreventsDataReleaseWithoutConsumingAnAttempt() throws Exception {
    initializeItem();

    for (int blockedRead = 0; blockedRead <= 9; blockedRead++) {
      final int failure = blockedRead;
      int[] calls = new int[1];
      OwnerPIN observed = new OwnerPIN(Safe.PIN_TRY_LIMIT, Safe.MAX_PIN_LENGTH) {
        @Override
        public byte getTriesRemaining() {
          return ++calls[0] == failure ? (byte) 0 : super.getTriesRemaining();
        }
      };
      observed.update(PIN, (short) 0, (byte) PIN.length);
      field("pin").set(safe, observed);
      calls[0] = 0;

      if (blockedRead == 0) {
        Assertions.assertArrayEquals(DATA, read(item.getData()));
      } else {
        assertDenied(() -> read(item.getData()));
      }

      Assertions.assertEquals(blockedRead == 0 ? 9 : blockedRead, calls[0]);
      Assertions.assertEquals(Safe.PIN_TRY_LIMIT, observed.getTriesRemaining());
      Assertions.assertArrayEquals(DATA, read(item.getData()));
    }
  }

  @Test
  public void anyBlockedReadAfterCheckingPINRevokesAuthorization() throws Exception {
    initializeItem();
    Field validation = field("pinBlockedValidation");
    LibSecurity.Condition original = (LibSecurity.Condition) validation.get(safe);

    for (int blockedRead = 1; blockedRead <= 3; blockedRead++) {
      authenticate(PIN);
      final int failure = blockedRead;
      int[] calls = new int[1];
      validation.set(safe, (LibSecurity.Condition) () -> ++calls[0] == failure || original.check());
      Assertions.assertFalse(checkPIN(WRONG_PIN));
      Assertions.assertEquals(blockedRead, calls[0]);
      validation.set(safe, original);
      Assertions.assertFalse(safe.isPINValidated());
      assertDenied(() -> item.getData());
      Assertions.assertEquals(4, safe.getPINTriesRemaining());
    }
  }

  @Test
  public void PINUpdatesRevokeAuthorizationAndRequireTheNewPIN() {
    initializeItem();
    updatePIN(NEW_PIN);
    Assertions.assertFalse(safe.isPINValidated());
    assertDenied(() -> item.getData());
    Assertions.assertFalse(checkPIN(PIN));
    authenticate(NEW_PIN);
    Assertions.assertArrayEquals(DATA, read(item.getData()));
  }

  @Test
  public void failingPINUpdatesRevokeAuthorizationAndPreserveThePIN() {
    initializeItem();
    Assertions.assertThrows(RuntimeException.class, () ->
      updatePIN(new byte[Safe.MAX_PIN_LENGTH + 1])
    );
    Assertions.assertFalse(safe.isPINValidated());
    assertDenied(() -> item.getData());
    authenticate(PIN);
    Assertions.assertArrayEquals(DATA, read(item.getData()));
  }

  @Test
  public void resetRevokesAuthorizationWhilePreservingItems() {
    initializeItem();
    simulator.reset();
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    Assertions.assertFalse(safe.isPINValidated());
    assertDenied(() -> item.getData());
    assertDenied(() -> updatePIN(NEW_PIN));
    authenticate(PIN);
    Assertions.assertArrayEquals(DATA, read(item.getData()));
  }

  @Test
  public void deselectPreservesInternalAuthorization() {
    initializeItem();
    Assertions.assertTrue(simulator.selectApplet(IDENTITY_AID));
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    Assertions.assertTrue(safe.isPINValidated());
    Assertions.assertArrayEquals(DATA, read(item.getData()));
  }

  @Test
  public void failedPINChecksRevokeAuthorizationAndConsumeOneAttempt() {
    initializeItem();
    Assertions.assertFalse(checkPIN(WRONG_PIN));
    Assertions.assertEquals(4, safe.getPINTriesRemaining());
    Assertions.assertFalse(safe.isPINValidated());
    assertDenied(() -> item.getData());
    authenticate(PIN);
    Assertions.assertArrayEquals(DATA, read(item.getData()));
  }

  @Test
  public void throwingPINChecksRevokeAuthorization() {
    initializeItem();
    Assertions.assertThrows(RuntimeException.class, () -> safe.checkPIN(null, (short) 0, (byte) 1));
    Assertions.assertFalse(safe.isPINValidated());
    assertDenied(() -> item.getData());
  }

  @Test
  public void exhaustedPINAttemptsPreventReauthorization() {
    initializeItem();

    for (byte remaining = 4; remaining >= 0; remaining--) {
      Assertions.assertFalse(checkPIN(WRONG_PIN));
      Assertions.assertEquals(remaining, safe.getPINTriesRemaining());
      Assertions.assertFalse(safe.isPINValidated());
      assertDenied(() -> item.getData());
    }

    Assertions.assertFalse(checkPIN(PIN));
    Assertions.assertEquals(0, safe.getPINTriesRemaining());
    assertDenied(() -> updatePIN(NEW_PIN));
  }

  @Test
  public void throwingOnTheLastPINAttemptPreventsReauthorization() {
    initializeItem();

    for (byte remaining = 4; remaining > 0; remaining--) {
      Assertions.assertFalse(checkPIN(WRONG_PIN));
      Assertions.assertEquals(remaining, safe.getPINTriesRemaining());
    }

    Assertions.assertThrows(RuntimeException.class, () -> safe.checkPIN(null, (short) 0, (byte) 1));
    Assertions.assertEquals(0, safe.getPINTriesRemaining());
    Assertions.assertFalse(safe.isPINValidated());
    assertDenied(() -> item.getData());
    assertDenied(() -> updatePIN(NEW_PIN));
  }

  @Test
  public void authorizationMustStayValidOnEveryReadBeforeReleasingData() throws Exception {
    initializeItem();
    short[] auth = (short[]) field("auth").get(safe);
    short[] valid = auth.clone();
    Field validation = field("authorizationValidation");
    LibSecurity.Condition original = (LibSecurity.Condition) validation.get(safe);

    for (int failedRead = 0; failedRead <= 9; failedRead++) {
      final int failure = failedRead;
      int[] calls = new int[1];
      System.arraycopy(valid, 0, auth, 0, auth.length);
      validation.set(
        safe,
        (LibSecurity.Condition) () -> {
          if (++calls[0] == failure) {
            auth[0] ^= 1;
          }

          return original.check();
        }
      );

      if (failedRead == 0) {
        Assertions.assertArrayEquals(DATA, read(item.getData()));
      } else {
        assertDenied(() -> read(item.getData()));
      }

      Assertions.assertEquals(failedRead == 0 ? 9 : failedRead, calls[0]);
    }

    validation.set(safe, original);
    System.arraycopy(valid, 0, auth, 0, auth.length);
    Assertions.assertArrayEquals(DATA, read(item.getData()));
  }

  @Test
  public void rejectsEverySingleBitChangeInAuthorization() throws Exception {
    initializeItem();
    short[] auth = (short[]) field("auth").get(safe);

    for (short[] valid : new short[][] { new short[2], auth.clone() }) {
      for (int word = 0; word < auth.length; word++) {
        for (int bit = 0; bit < 16; bit++) {
          System.arraycopy(valid, 0, auth, 0, auth.length);
          auth[word] ^= (short) (1 << bit);
          assertDenied(() -> safe.isPINValidated());
          assertDenied(() -> item.getData());
          assertDenied(() -> updatePIN(NEW_PIN));
        }
      }
    }
  }

  @Test
  public void rejectsInvalidAuthorizationCodesEvenWithMatchingComplements() throws Exception {
    initializeItem();
    short[] auth = (short[]) field("auth").get(safe);

    for (short invalid : new short[] { 0, 1, -1, (short) 0xA501 }) {
      auth[0] = invalid;
      auth[1] = (short) ~invalid;
      assertDenied(() -> safe.isPINValidated());
      assertDenied(() -> item.getData());
    }
  }

  @Test
  public void resettingTheNativePINFlagPreservesInternalAuthorization() throws Exception {
    initializeItem();
    ((OwnerPIN) field("pin").get(safe)).reset();
    Assertions.assertTrue(safe.isPINValidated());
    Assertions.assertArrayEquals(DATA, read(item.getData()));
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
          assertDenied(() -> safe.isPINSet());
          assertDenied(() -> safe.list((short) 0));
          assertDenied(() -> updatePIN(NEW_PIN));
        }
      }

      for (short invalid : new short[] { 0, 1, -1 }) {
        state.setShort(safe, invalid);
        inverse.setShort(safe, (short) ~invalid);
        assertDenied(() -> safe.isPINSet());
        assertDenied(() -> updatePIN(NEW_PIN));
      }

      state.setShort(safe, validState);
      inverse.setShort(safe, validInverse);
    }
  }

  private void initializeItem() {
    updatePIN(PIN);
    authenticate(PIN);
    item = safe.create(INDEX, null, null, new TestData(DATA), false);
  }

  private boolean checkPIN(byte[] pin) {
    return safe.checkPIN(pin, (short) 0, (byte) pin.length);
  }

  private void updatePIN(byte[] pin) {
    safe.updatePIN(pin, (short) 0, (byte) pin.length);
  }

  private void authenticate(byte[] pin) {
    Assertions.assertTrue(checkPIN(pin));
    Assertions.assertTrue(safe.isPINValidated());
  }

  private Field field(String name) throws Exception {
    Field field = Safe.class.getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private void assertDenied(Executable operation) {
    ISOException exception = Assertions.assertThrows(ISOException.class, operation);
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
  }
}
