package monoidsecuritykey;

import com.licel.jcardsim.base.TransientMemory;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.nio.charset.StandardCharsets;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.SystemException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoid.Monoid;
import monoid.SafeDataShareable;
import monoid.SafeItemIteratorShareable;
import monoid.SafeItemShareable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CommandResetTest {

  private static final AID MONOID_AID = new AID(
    Constants.MONOID_AID,
    (short) 0,
    (byte) Constants.MONOID_AID.length
  );
  private static final AID FIDO_AID = AIDUtil.create("a0000006472f0001");
  private static final byte[] PIN = "314159".getBytes(StandardCharsets.UTF_8);

  private FailingTransientMemory memory;
  private CardSimulator simulator;
  private ClientPIN pin;

  @BeforeEach
  public void initialize() throws Exception {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    memory = new FailingTransientMemory();
    simulator = new CardSimulator(new ShareableSimulatorRuntime(memory));
    simulator.installApplet(MONOID_AID, StorageApplet.class);
    byte[] parameters = new byte[] { 0, 0, 0 };
    simulator.installApplet(
      FIDO_AID,
      MonoidSecurityKeyApplet.class,
      parameters,
      (short) 0,
      (byte) parameters.length
    );
    Assertions.assertTrue(simulator.selectApplet(FIDO_AID));
    pin = Command.authenticator.pin;
    new ClientPINTest.Host(pin).setPIN(PIN);
  }

  @AfterEach
  public void dispose() {
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
    simulator.deleteApplet(FIDO_AID);
    simulator.deleteApplet(MONOID_AID);
    Command.dispose();
    StorageApplet.instance = null;
  }

  @Test
  public void refusedRemovalLeavesCredentialsAndPINForRetry() throws Exception {
    StorageApplet.instance.denyRemoval = true;
    assertReset(CTAP.OPERATION_DENIED);
    Assertions.assertEquals(2, StorageApplet.instance.records);
    Assertions.assertTrue(pin.isSet());
    new ClientPINTest.Host(pin).getToken(PIN);

    StorageApplet.instance.denyRemoval = false;
    assertReset((short) 0);
    Assertions.assertEquals(0, StorageApplet.instance.records);
    Assertions.assertFalse(pin.isSet());
  }

  @Test
  public void PINAllocationFailureKeepsRemovalAndCanBeRetried() throws Exception {
    memory.failNextBooleanArray = true;
    assertReset(CTAP.OTHER);
    Assertions.assertFalse(memory.failNextBooleanArray);
    Assertions.assertEquals(0, memory.failureDepth);
    Assertions.assertEquals(0, StorageApplet.instance.records);
    Assertions.assertTrue(pin.isSet());
    new ClientPINTest.Host(pin).getToken(PIN);

    assertReset((short) 0);
    Assertions.assertEquals(2, StorageApplet.instance.removeCalls);
    Assertions.assertEquals(0, StorageApplet.instance.records);
    Assertions.assertFalse(pin.isSet());
  }

  @Test
  public void completedResetCanBeRepeated() {
    assertReset((short) 0);
    assertReset((short) 0);
    Assertions.assertEquals(2, StorageApplet.instance.removeCalls);
    Assertions.assertEquals(0, StorageApplet.instance.records);
    Assertions.assertFalse(pin.isSet());
    Assertions.assertEquals(8, pin.getRetries());
  }

  private void assertReset(short status) {
    ResponseAPDU response = simulator.transmitCommand(
      new CommandAPDU(0x80, 0x10, 0, 0, new byte[] { 7 }, 256)
    );
    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertArrayEquals(new byte[] { (byte) status }, response.getData());
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
  }

  private static final class FailingTransientMemory extends TransientMemory {

    boolean failNextBooleanArray;
    byte failureDepth;

    @Override
    public boolean[] makeBooleanArray(short length, byte event) {
      if (failNextBooleanArray) {
        // jCardSim's OwnerPIN constructor allocates its validated flag here.
        // This injects allocation failure; no persistent rollback is simulated.
        failNextBooleanArray = false;
        failureDepth = JCSystem.getTransactionDepth();
        SystemException.throwIt(SystemException.NO_TRANSIENT_SPACE);
      }
      return super.makeBooleanArray(length, event);
    }
  }

  public static final class StorageApplet extends Applet implements Monoid {

    static StorageApplet instance;
    boolean denyRemoval;
    short records = 2;
    short removeCalls;

    public static void install(byte[] buffer, short offset, byte length) {
      instance = new StorageApplet();
      instance.register();
    }

    @Override
    public void process(APDU apdu) {}

    @Override
    public Shareable getShareableInterfaceObject(AID caller, byte parameter) {
      return this;
    }

    @Override
    public void authenticate(byte[] token) {
      Assertions.assertEquals(32, token.length);
    }

    @Override
    public void authenticate(byte[] token, short offset) {
      Assertions.assertTrue(offset >= 0 && offset <= token.length - 32);
    }

    @Override
    public void removeAll(short type) {
      Assertions.assertEquals(Constants.CREDENTIAL_TYPE, type);
      Assertions.assertEquals(0, JCSystem.getTransactionDepth());
      removeCalls++;
      if (denyRemoval) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }
      JCSystem.beginTransaction();
      records = 0;
      JCSystem.commitTransaction();
    }

    @Override
    public short getMonoid001PublicKey(byte[] context, byte[] dest, short offset) {
      throw new AssertionError("Unexpected key request during Reset");
    }

    @Override
    public short getMonoid001PublicKey(
      byte[] context,
      short contextOffset,
      short contextLength,
      byte[] dest,
      short offset
    ) {
      throw new AssertionError("Unexpected key request during Reset");
    }

    @Override
    public short signMonoid001ECDSADigest(
      byte[] context,
      byte[] digest,
      byte[] dest,
      short offset
    ) {
      throw new AssertionError("Unexpected signature request during Reset");
    }

    @Override
    public short signMonoid001ECDSADigest(
      byte[] context,
      short contextOffset,
      short contextLength,
      byte[] digest,
      short digestOffset,
      byte[] dest,
      short offset
    ) {
      throw new AssertionError("Unexpected signature request during Reset");
    }

    @Override
    public SafeItemIteratorShareable list(short type) {
      throw new AssertionError("Unexpected enumeration during Reset");
    }

    @Override
    public SafeItemIteratorShareable list(short type, byte[] keyPrefix) {
      throw new AssertionError("Unexpected enumeration during Reset");
    }

    @Override
    public short listIndices(
      short type,
      byte[] keyPrefix,
      short keyOffset,
      short keyLength,
      byte[] dest,
      short offset,
      short capacity
    ) {
      throw new AssertionError("Unexpected enumeration during Reset");
    }

    @Override
    public SafeItemShareable get(byte[] index) {
      throw new AssertionError("Unexpected item lookup during Reset");
    }

    @Override
    public SafeDataShareable getData(
      byte[] index,
      short indexOffset,
      byte[] expectedKey,
      short keyOffset,
      short keyLength
    ) {
      throw new AssertionError("Unexpected data lookup during Reset");
    }

    @Override
    public boolean isDataCurrent(SafeDataShareable data) {
      throw new AssertionError("Unexpected data validation during Reset");
    }

    @Override
    public short readData(
      byte[] index,
      byte[] expectedKey,
      byte[] dest,
      short offset,
      short capacity
    ) {
      throw new AssertionError("Unexpected data lookup during Reset");
    }

    @Override
    public short readData(
      byte[] index,
      short indexOffset,
      byte[] expectedKey,
      short keyOffset,
      short keyLength,
      byte[] dest,
      short offset,
      short capacity
    ) {
      throw new AssertionError("Unexpected data lookup during Reset");
    }

    @Override
    public SafeItemShareable create(
      byte[] index,
      byte[] key,
      byte[] alias,
      SafeDataShareable data,
      boolean secret
    ) {
      throw new AssertionError("Unexpected item creation during Reset");
    }

    @Override
    public boolean createData(
      byte[] index,
      short indexOffset,
      byte[] key,
      short keyOffset,
      short keyLength,
      byte[] alias,
      byte[] data,
      short dataOffset,
      short dataLength,
      boolean secret
    ) {
      throw new AssertionError("Unexpected item creation during Reset");
    }
  }
}
