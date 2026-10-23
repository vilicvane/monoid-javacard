package monoid;

import static monoid.TestData.read;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoididentity.MonoidIdentityApplet;
import monoidlib.CBORBufferWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

public class SafeAuthenticationTest {

  private static final AID IDENTITY_AID = AIDUtil.create(
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
  private static final byte[] INDEX = { 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
  private static final byte[] DATA = { (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF };

  private CardSimulator simulator;
  private Safe safe;
  private SafeItem item;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    simulator = new CardSimulator(new ShareableSimulatorRuntime());
    simulator.installApplet(IDENTITY_AID, MonoidIdentityApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    safe = MonoidApplet.safe;
    safe.initializeIdentity();
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(MONOID_AID);
    simulator.deleteApplet(IDENTITY_AID);
  }

  @Test
  public void storageAuthorizationRequiresAnAuthenticatedCommand() {
    Assertions.assertFalse(safe.isPINSet());
    assertDenied(() -> safe.list((short) 0));
    safe.updatePIN(PIN);
    Assertions.assertTrue(safe.checkPIN(PIN));
    Assertions.assertTrue(safe.isPINValidated());
    assertDenied(() -> safe.list((short) 0));
    Assertions.assertThrows(MonoidException.class, safe::checkAccess);
    authenticate(PIN);
    Assertions.assertEquals(0, safe.list((short) 0).getCount());
  }

  @Test
  public void failedSecretPINVerificationRevokesLocalStorageAuthorization() {
    initializeItem();
    Assertions.assertFalse(safe.checkPIN(WRONG_PIN));
    Assertions.assertEquals(4, safe.getPINTriesRemaining());
    Assertions.assertFalse(safe.isPINValidated());
    assertDenied(() -> item.getData());
    authenticate(PIN);
    Assertions.assertArrayEquals(DATA, read(item.getData()));
  }

  @Test
  public void PINChangesRevokeStorageAuthorization() {
    initializeItem();
    safe.updatePIN(NEW_PIN);
    Assertions.assertFalse(safe.isPINValidated());
    assertDenied(() -> item.getData());
    authenticate(NEW_PIN);
    Assertions.assertArrayEquals(DATA, read(item.getData()));
  }

  @Test
  public void cardResetRevokesStorageAuthorizationWhilePreservingItems() {
    initializeItem();
    simulator.reset();
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    Assertions.assertFalse(safe.isPINValidated());
    assertDenied(() -> item.getData());
    authenticate(PIN);
    Assertions.assertArrayEquals(DATA, read(item.getData()));
  }

  @Test
  public void deselectPreservesInternalAuthorizationButClearsCommandAuthorization() {
    initializeItem();
    Assertions.assertTrue(simulator.selectApplet(IDENTITY_AID));
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    Assertions.assertEquals(0, Command.getAuth());
    Assertions.assertTrue(safe.isPINValidated());
    Assertions.assertArrayEquals(DATA, read(item.getData()));
  }

  @Test
  public void storageReadsDoNotReenterIdentity() throws Exception {
    initializeItem();

    for (String name : new String[] { "pinSetValidation", "pinBlockedValidation" }) {
      Field field = field(name);
      field.set(
        safe,
        (LibSecurity.Condition) () -> {
          Assertions.fail("Storage callbacks must only use their local authorization.");
          return false;
        }
      );
    }

    Assertions.assertArrayEquals(DATA, read(item.getData()));
    Assertions.assertEquals(1, safe.list((short) 0).getCount());
  }

  @Test
  public void authorizationMustStayValidBeforeReleasingData() throws Exception {
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
  }

  @Test
  public void rejectsSingleBitChangesInLocalStorageAuthorization() throws Exception {
    initializeItem();
    short[] auth = (short[]) field("auth").get(safe);

    for (short[] valid : new short[][] { new short[2], auth.clone() }) {
      for (int word = 0; word < auth.length; word++) {
        for (int bit = 0; bit < 16; bit++) {
          System.arraycopy(valid, 0, auth, 0, auth.length);
          auth[word] ^= (short) (1 << bit);
          assertDenied(() -> item.getData());
        }
      }
    }
  }

  private void initializeItem() {
    safe.updatePIN(PIN);
    authenticate(PIN);
    item = safe.create(INDEX, null, null, new TestData(DATA), false);
  }

  private void authenticate(byte[] pin) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    writer.text(Text.secret);
    writer.bool(true);
    writer.text(Text.pin);
    writer.text(pin);
    ResponseAPDU response = simulator.transmitCommand(
      new CommandAPDU(0, 0x21, 0, 0, writer.getDataBuffer())
    );
    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertEquals(Command.AUTH_SECRET, Command.getAuth());
    Assertions.assertTrue(safe.isPINValidated());
    safe.checkAccess();
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
