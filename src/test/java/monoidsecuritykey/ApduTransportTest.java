package monoidsecuritykey;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacardx.apdu.ExtendedLength;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoidlib.CBORApduWriter;
import monoidlib.CBORBufferWriter;
import monoidlib.CBORMap;
import monoidlib.CBORReader;
import monoidlib.CBORWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ApduTransportTest {

  private static final AID APPLET_AID = AIDUtil.create("f06d6f6e6f69647f01");
  private static final AID OTHER_AID = AIDUtil.create("f06d6f6e6f69647f02");

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    simulator = new CardSimulator();
    simulator.installApplet(APPLET_AID, TransportApplet.class);
    Assertions.assertTrue(simulator.selectApplet(APPLET_AID));
  }

  @AfterEach
  public void dispose() {
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
    Command.dispose();
    TransportApplet.installedTransport = null;
  }

  @Test
  public void forwardedSelectReturnsFileNotFoundEvenWhenCtapIsDisabled() throws Exception {
    for (boolean disabled : new boolean[] { false, true }) {
      if (disabled) {
        Assertions.assertEquals(
          0x9000,
          simulator.transmitCommand(new CommandAPDU(0x80, 0x12, 1, 0)).getSW()
        );
      }

      byte[] aid = { (byte) 0xF0, 1, 2, 3, 4 };
      ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(0, 0xA4, 4, 0, aid));
      Assertions.assertEquals(0x6A82, response.getSW());
      Assertions.assertEquals(0, response.getData().length);

      inject(new TestCommand((short) 0));
      if (disabled) {
        Assertions.assertEquals(
          0x6985,
          simulator.transmitCommand(new CommandAPDU(0x80, 0x10, 0, 0, new byte[] { 1 })).getSW()
        );
      } else {
        assertResponse((short) 0);
      }
    }
  }

  @Test
  public void forwardedSelectDiscardsPendingRequestsAndResponses() throws Exception {
    PayloadCommand command = new PayloadCommand(60, 256);
    inject(command);

    for (boolean request : new boolean[] { true, false }) {
      ResponseAPDU pending = simulator.transmitCommand(
        new CommandAPDU(request ? 0x90 : 0x80, 0x10, 0, 0, new byte[] { 1 }, 17)
      );
      Assertions.assertEquals(request ? 0x90 : 0x61, pending.getSW1());

      Assertions.assertEquals(
        0x6A82,
        simulator
          .transmitCommand(new CommandAPDU(0, 0xA4, 4, 0, new byte[] { (byte) 0xF0, 1, 2, 3, 4 }))
          .getSW()
      );
      Assertions.assertEquals(
        0x6985,
        simulator.transmitCommand(new CommandAPDU(0, 0xC0, 0, 0, 256)).getSW()
      );
      Assertions.assertArrayEquals(command.expected(), response(256));
    }
  }

  @Test
  public void preservesCTAPErrorsAndAcceptsTheNextCommand() throws Exception {
    assertFailureAndRetry(CTAP.PIN_AUTH_INVALID, CTAP.PIN_AUTH_INVALID);
  }

  @Test
  public void mapsStorageErrorsToKeyStoreFull() throws Exception {
    assertFailureAndRetry(ISO7816.SW_FILE_FULL, CTAP.KEY_STORE_FULL);
  }

  @Test
  public void mapsAuthorizationAndStateErrorsToOperationDenied() throws Exception {
    assertFailureAndRetry(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, CTAP.OPERATION_DENIED);
    assertFailureAndRetry(ISO7816.SW_CONDITIONS_NOT_SATISFIED, CTAP.OPERATION_DENIED);
  }

  @Test
  public void mapsOtherISOErrorsToOther() throws Exception {
    assertFailureAndRetry(ISO7816.SW_UNKNOWN, CTAP.OTHER);
  }

  @Test
  public void mapsRuntimeErrorsToOther() throws Exception {
    assertFailureAndRetry((short) -1, CTAP.OTHER);
  }

  @Test
  public void preservesScalarAndBulkWritesAcrossWindowAndResponseBoundaries() throws Exception {
    for (int prefix : new int[] { 60, 61, 62 }) {
      for (int length : new int[] { 0, 1, 63, 64, 65, 255, 256 }) {
        PayloadCommand command = new PayloadCommand(prefix, length);
        inject(command);
        Assertions.assertArrayEquals(command.expected(), response(17));
      }
    }
  }

  @Test
  public void directRepliesPreserveThePersistentResponseUntilTheyExceedCapacity() throws Exception {
    simulator.changeProtocol("T=1");
    inject(new TestCommand((short) 0));
    assertResponse((short) 0);
    byte[] stored = persistentResponse();
    for (int capacity : new int[] { 133, 260 }) {
      for (int length : new int[] { capacity - 69, capacity - 68, capacity - 67 }) {
        PayloadCommand command = new PayloadCommand(60, length, capacity);
        inject(command);
        Arrays.fill(stored, (byte) 0x5a);
        byte[] expected = command.expected();
        Assertions.assertArrayEquals(expected, response(32767));
        if (expected.length <= capacity) {
          byte[] untouched = new byte[stored.length];
          Arrays.fill(untouched, (byte) 0x5a);
          Assertions.assertArrayEquals(untouched, stored);
        } else {
          Assertions.assertArrayEquals(expected, Arrays.copyOf(stored, expected.length));
        }
      }
    }
  }

  @Test
  public void directRepliesAreSavedBeforeSmallLeGetResponse() throws Exception {
    for (int capacity : new int[] { 133, 260 }) {
      for (int expected : new int[] { 1, 17, 64, 256 }) {
        PayloadCommand command = new PayloadCommand(60, 60, capacity);
        inject(command);
        Assertions.assertArrayEquals(command.expected(), response(expected));
      }
    }
  }

  @Test
  public void directErrorsAndCancellationDiscardAllUnsentBytes() throws Exception {
    for (short reason : new short[] { CTAP.PIN_AUTH_INVALID, -1 }) {
      inject(new TestCommand(reason, (short) 133));
      assertResponse(reason < 0 ? CTAP.OTHER : reason);
      PayloadCommand next = new PayloadCommand(60, 60, 133);
      inject(next);
      Assertions.assertArrayEquals(next.expected(), response(256));
    }

    simulator.installApplet(OTHER_AID, EmptyApplet.class);
    for (boolean deselect : new boolean[] { false, true }) {
      inject(new PayloadCommand(60, 60, 133));
      ResponseAPDU first = simulator.transmitCommand(
        new CommandAPDU(0x80, 0x10, 0, 0, new byte[] { 1 }, 17)
      );
      Assertions.assertEquals(0x61, first.getSW1());
      if (deselect) {
        reselect();
      } else {
        inject(new TestCommand((short) 0));
        assertResponse((short) 0);
      }
      Assertions.assertEquals(
        0x6985,
        simulator.transmitCommand(new CommandAPDU(0, 0xC0, 0, 0, 256)).getSW()
      );
    }
  }

  @Test
  public void largeResidentUserRepliesUseTheExistingResponseFallback() throws Exception {
    UserCommand command = new UserCommand();
    inject(command);
    byte[] expected = command.expected();
    Assertions.assertTrue(expected.length > 260);
    Assertions.assertArrayEquals(expected, response(256));
    Assertions.assertArrayEquals(expected, response(17));
  }

  @Test
  public void clientPinAgreementKeepsItsUnreadPointOutsideTheWriterWindow() {
    byte[] point = new byte[65];
    Command.authenticator.pin.getKeyAgreement(point, (short) 0);
    ResponseAPDU response = simulator.transmitCommand(
      new CommandAPDU(0x80, 0x10, 0, 0, new byte[] { 6, (byte) 0xa2, 1, 1, 2, 2 }, 256)
    );
    Assertions.assertEquals(0x9000, response.getSW());
    byte[] data = response.getData();
    Assertions.assertEquals(0, data[0]);
    CBORReader reader = new CBORReader(data, (short) 1, (short) (data.length - 1));
    CBORMap fields = reader.map(new short[] { 1 });
    Assertions.assertArrayEquals(point, LibCOSE.readKeyAgreement(fields.requireKey((short) 1)));
  }

  @Test
  public void preservesTheResponseLimitAndRecoversAfterOverflow() throws Exception {
    PayloadCommand command = new PayloadCommand(60, 955);
    inject(command);
    byte[] data = response(256);
    Assertions.assertEquals(1024, data.length);
    Assertions.assertArrayEquals(command.expected(), data);

    inject(new PayloadCommand(60, 956));
    assertResponse(CTAP.LIMIT_EXCEEDED);
    inject(command);
    Assertions.assertArrayEquals(command.expected(), response(256));
  }

  @Test
  public void returnsCompleteExtendedResponsesWithoutGetResponse() throws Exception {
    simulator.changeProtocol("T=1");
    for (int length : new int[] { 0, 256, 955 }) {
      PayloadCommand command = new PayloadCommand(60, length);
      inject(command);
      // jCardSim does not normalize extended Le=0000 to the JCRE maximum of 32767.
      ResponseAPDU response = simulator.transmitCommand(
        new CommandAPDU(0x80, 0x10, 0, 0, new byte[] { 1 }, 32767)
      );

      Assertions.assertEquals(0x9000, response.getSW());
      Assertions.assertArrayEquals(command.expected(), response.getData());
    }
  }

  @Test
  public void deselectionDiscardsPendingResponsesAndChainedRequests() throws Exception {
    simulator.installApplet(OTHER_AID, EmptyApplet.class);
    PayloadCommand command = new PayloadCommand(60, 256);
    inject(command);
    ResponseAPDU first = simulator.transmitCommand(
      new CommandAPDU(0x80, 0x10, 0, 0, new byte[] { 1 }, 17)
    );
    Assertions.assertEquals(0x61, first.getSW1());
    reselect();
    Assertions.assertEquals(
      0x6985,
      simulator.transmitCommand(new CommandAPDU(0, 0xC0, 0, 0, 256)).getSW()
    );
    Assertions.assertArrayEquals(command.expected(), response(256));

    Assertions.assertEquals(
      0x9000,
      simulator.transmitCommand(new CommandAPDU(0x90, 0x10, 0, 0, new byte[] { 1 })).getSW()
    );
    reselect();
    Assertions.assertArrayEquals(command.expected(), response(256));
  }

  private void reselect() {
    Assertions.assertTrue(simulator.selectApplet(OTHER_AID));
    Assertions.assertTrue(simulator.selectApplet(APPLET_AID));
  }

  private byte[] response(int expected) {
    ResponseAPDU response = simulator.transmitCommand(
      new CommandAPDU(0x80, 0x10, 0, 0, new byte[] { 1 }, expected)
    );
    ByteArrayOutputStream data = new ByteArrayOutputStream();
    while (true) {
      byte[] chunk = response.getData();
      data.write(chunk, 0, chunk.length);
      if (response.getSW1() != 0x61) {
        Assertions.assertEquals(0x9000, response.getSW());
        return data.toByteArray();
      }
      Assertions.assertEquals(expected, chunk.length);
      response = simulator.transmitCommand(new CommandAPDU(0, 0xC0, 0, 0, expected));
    }
  }

  private void assertFailureAndRetry(short reason, short status) throws Exception {
    inject(new TestCommand(reason));
    assertResponse(status);
    inject(new TestCommand((short) 0));
    assertResponse((short) 0);
  }

  private void inject(Command command) throws Exception {
    Field field = Command.class.getDeclaredField("makeCredential");
    field.setAccessible(true);
    field.set(null, command);
  }

  private byte[] persistentResponse() throws Exception {
    Field field = ApduTransport.class.getDeclaredField("response");
    field.setAccessible(true);
    return (byte[]) field.get(TransportApplet.installedTransport);
  }

  private void assertResponse(short status) {
    ResponseAPDU response = simulator.transmitCommand(
      new CommandAPDU(0x80, 0x10, 0, 0, new byte[] { 1 }, 256)
    );
    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertArrayEquals(new byte[] { (byte) status }, response.getData());
  }

  private static final class TestCommand extends Command {

    private final short result;
    private final short directCapacity;

    TestCommand(short result) {
      this(result, (short) 0);
    }

    TestCommand(short result, short directCapacity) {
      this.result = result;
      this.directCapacity = directCapacity;
    }

    @Override
    void execute(CBORReader reader, CBORWriter writer) {
      if (directCapacity != 0) {
        ((CBORApduWriter) writer).reset((short) 1, directCapacity);
      }
      if (result != 0) {
        // Leave both a committed window and an uncommitted byte before the failure.
        for (short index = 0; index < 65; index++) {
          writer.bool(true);
        }
      }
      if (result == -1) {
        SystemException.throwIt(SystemException.NO_RESOURCE);
      } else if (result != 0) {
        ISOException.throwIt(result);
      }
    }
  }

  private static final class PayloadCommand extends Command {

    private final short prefix;
    private final byte[] data;
    private final short directCapacity;

    PayloadCommand(int prefix, int length) {
      this(prefix, length, 0);
    }

    PayloadCommand(int prefix, int length, int directCapacity) {
      this.prefix = (short) prefix;
      this.directCapacity = (short) directCapacity;
      data = new byte[length];
      for (int index = 0; index < length; index++) {
        data[index] = (byte) index;
      }
    }

    @Override
    void execute(CBORReader reader, CBORWriter writer) {
      assertEmpty(reader);
      if (directCapacity != 0) {
        ((CBORApduWriter) writer).reset((short) 1, directCapacity);
      }
      writer.array((short) (prefix + 2));
      for (short index = 0; index < prefix; index++) {
        writer.bool((index & 1) != 0);
      }
      writer.bytes(data);
      writer.integer((short) 256);
    }

    byte[] expected() {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      output.write(0);
      output.write(0x98);
      output.write(prefix + 2);
      for (int index = 0; index < prefix; index++) {
        output.write((index & 1) != 0 ? 0xF5 : 0xF4);
      }
      if (data.length < 24) {
        output.write(0x40 + data.length);
      } else if (data.length < 256) {
        output.write(0x58);
        output.write(data.length);
      } else {
        output.write(0x59);
        output.write(data.length >> 8);
        output.write(data.length);
      }
      output.write(data, 0, data.length);
      output.write(0x19);
      output.write(1);
      output.write(0);
      return output.toByteArray();
    }
  }

  private static final class UserCommand extends Command {

    private final byte[] authData = new byte[37];
    private final byte[] signature = new byte[71];
    private final Credential credential = new Credential(
      new byte[32],
      new byte[32],
      new byte[32],
      new byte[0],
      new byte[64],
      new byte[64],
      new byte[64],
      new byte[65]
    );

    @Override
    void execute(CBORReader reader, CBORWriter writer) {
      assertEmpty(reader);
      ((CBORApduWriter) writer).reset((short) 1, (short) 260);
      encode(writer);
    }

    byte[] expected() {
      byte[] data = new byte[1024];
      CBORBufferWriter writer = new CBORBufferWriter(data, (short) 1, CTAP.LIMIT_EXCEEDED);
      encode(writer);
      return Arrays.copyOf(data, writer.getLength() + 1);
    }

    private void encode(CBORWriter writer) {
      writer.map((short) 4);
      writer.integer((short) 1);
      credential.writeDescriptor(writer);
      writer.integer((short) 2);
      writer.bytes(authData);
      writer.integer((short) 3);
      writer.bytes(signature);
      writer.integer((short) 4);
      credential.writeUser(writer, true);
    }
  }

  public static final class TransportApplet extends Applet implements ExtendedLength {

    private static ApduTransport installedTransport;
    private final ApduTransport transport = new ApduTransport();

    public static void install(byte[] buffer, short offset, byte length) {
      Command.init();
      TransportApplet applet = new TransportApplet();
      installedTransport = applet.transport;
      applet.register();
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        transport.clear();
        return;
      }
      transport.process(apdu);
    }

    @Override
    public void deselect() {
      transport.clear();
      Command.clear();
    }
  }

  public static final class EmptyApplet extends Applet {

    public static void install(byte[] buffer, short offset, byte length) {
      new EmptyApplet().register();
    }

    @Override
    public void process(APDU apdu) {}
  }
}
