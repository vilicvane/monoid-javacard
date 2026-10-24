package monoidlib;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ApduTransportTest {

  private static final AID TRANSPORT_AID = AIDUtil.create("f06d6f6e6f69647f01");

  private static EchoTransport[] installed;

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");

    simulator = new CardSimulator();
    simulator.installApplet(TRANSPORT_AID, TransportApplet.class);
    Assertions.assertTrue(simulator.selectApplet(TRANSPORT_AID));
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(TRANSPORT_AID);
    installed = null;
  }

  @Test
  public void interleavedInstancesKeepIndependentRequestChains() {
    assertSuccess(transmit(0x90, 1, 0, new byte[] { 0x43, 1 }), new byte[0]);
    assertSuccess(transmit(0x90, 1, 1, new byte[] { 0x42, 4 }), new byte[0]);

    Assertions.assertTrue(installed[0].isReceiving());
    Assertions.assertTrue(installed[1].isReceiving());

    assertSuccess(transmit(0xA0, 1, 0, new byte[] { 2, 3 }), new byte[] { 0x43, 1, 2, 3 });

    Assertions.assertFalse(installed[0].isReceiving());
    Assertions.assertTrue(installed[1].isReceiving());
    Assertions.assertEquals(1, installed[0].executions);
    Assertions.assertEquals(0, installed[1].executions);

    assertSuccess(transmit(0xA0, 1, 1, new byte[] { 5 }), new byte[] { 0x42, 4, 5 });

    Assertions.assertFalse(installed[1].isReceiving());
    Assertions.assertEquals(1, installed[1].executions);
  }

  @Test
  public void unsupportedInstructionIsRejectedBeforeReadingAndClearsTheChain() {
    assertSuccess(transmit(0x90, 1, 0, new byte[] { 0x42, 1 }), new byte[0]);

    ResponseAPDU rejected = simulator.transmitCommand(new CommandAPDU(0, 0x7F, 0, 0));

    // Reading this case-1 command as an incoming request would fail with 6700.
    Assertions.assertEquals(0x6D00, rejected.getSW());
    Assertions.assertFalse(installed[0].isReceiving());
    Assertions.assertEquals(0, installed[0].reader.getReceivedLength());
    Assertions.assertEquals(0, installed[0].executions);
    Assertions.assertEquals(0x6883, transmit(0xA0, 1, 0, new byte[] { 2 }).getSW());

    assertSuccess(transmit(0, 1, 0, new byte[] { 0x41, 3 }), new byte[] { 0x41, 3 });
    Assertions.assertEquals(1, installed[0].executions);
  }

  private ResponseAPDU transmit(int cla, int instruction, int transport, byte[] data) {
    return simulator.transmitCommand(new CommandAPDU(cla, instruction, transport, 0, data));
  }

  private void assertSuccess(ResponseAPDU response, byte[] data) {
    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertArrayEquals(data, response.getData());
  }

  private static final class EchoTransport extends ApduTransport {

    private final CBORApduReader reader;
    private final CBORApduWriter writer;

    private int executions;

    EchoTransport() {
      this(new CBORApduReader(), new CBORApduWriter());
    }

    private EchoTransport(CBORApduReader reader, CBORApduWriter writer) {
      super(reader, writer);
      this.reader = reader;
      this.writer = writer;
    }

    @Override
    protected boolean supports(byte instruction) {
      return instruction == 1;
    }

    @Override
    protected void execute(byte instruction) {
      executions++;
      writer.bytes(reader.bytes());
      writer.send();
    }
  }

  public static final class TransportApplet extends Applet {

    private final EchoTransport[] transports = { new EchoTransport(), new EchoTransport() };

    public static void install(byte[] buffer, short offset, byte length) {
      TransportApplet applet = new TransportApplet();
      installed = applet.transports;
      applet.register();
    }

    @Override
    public void deselect() {
      super.deselect();

      for (EchoTransport transport : transports) {
        transport.clear();
      }
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        for (EchoTransport transport : transports) {
          transport.clear();
        }

        return;
      }

      transports[apdu.getBuffer()[ISO7816.OFFSET_P1]].process(apdu);
    }
  }
}
