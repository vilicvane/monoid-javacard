package monoid;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CBORApduWriterTest {

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");

    simulator = new CardSimulator();
    AID aid = AIDUtil.create("f06d6f6e6f69647f01");
    simulator.installApplet(aid, WriterApplet.class);
    Assertions.assertTrue(simulator.selectApplet(aid));
  }

  @Test
  public void releasesBufferAfterLastResponseChunk() {
    ResponseAPDU first = transmit(0x20);
    byte[] buffer = Command.writer.buffer;
    byte[] expected = new byte[603];
    expected[0] = 0x59;
    expected[1] = 0x02;
    expected[2] = 0x58;
    Arrays.fill(expected, 3, expected.length, (byte) 0xA5);

    Assertions.assertEquals(0x6100, first.getSW());
    Assertions.assertArrayEquals(Arrays.copyOfRange(expected, 0, 256), first.getData());
    Assertions.assertTrue(Command.writer.hasPending());
    Assertions.assertArrayEquals(new byte[256], Arrays.copyOf(buffer, 256));

    ResponseAPDU second = transmit(0xC0);

    Assertions.assertEquals(0x615B, second.getSW());
    Assertions.assertArrayEquals(Arrays.copyOfRange(expected, 256, 512), second.getData());
    Assertions.assertSame(buffer, Command.writer.buffer);

    ResponseAPDU last = transmit(0xC0);

    Assertions.assertEquals(0x9000, last.getSW());
    Assertions.assertArrayEquals(Arrays.copyOfRange(expected, 512, 603), last.getData());
    assertReleased(buffer);
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());

    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
    Assertions.assertNotSame(buffer, Command.writer.buffer);
  }

  @Test
  public void releasesCancelledResponseBeforeNewCommand() {
    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
    byte[] buffer = Command.writer.buffer;

    Assertions.assertEquals(0x6D00, transmit(0x7F).getSW());

    assertReleased(buffer);
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());
  }

  @Test
  public void releasesPendingResponseOnDeselect() {
    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
    byte[] buffer = Command.writer.buffer;
    AID other = AIDUtil.create("f06d6f6e6f69647f02");
    simulator.installApplet(other, EmptyApplet.class);

    Assertions.assertTrue(simulator.selectApplet(other));

    assertReleased(buffer);
  }

  @Test
  public void releasesResponseWhenSendFails() {
    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
    byte[] buffer = Command.writer.buffer;

    Assertions.assertEquals(0x6F00, transmit(0x7E).getSW());

    assertReleased(buffer);
  }

  private ResponseAPDU transmit(int instruction) {
    return new ResponseAPDU(
      simulator.transmitCommand(
        new CommandAPDU(0, instruction, 0, 0, new byte[] { (byte) 0xA0 }).getBytes()
      )
    );
  }

  private void assertReleased(byte[] buffer) {
    Assertions.assertArrayEquals(new byte[buffer.length], buffer);
    Assertions.assertNull(Command.writer.buffer);
    Assertions.assertEquals(0, Command.writer.getLength());
    Assertions.assertFalse(Command.writer.hasPending());
  }

  public static class WriterApplet extends MonoidApplet {

    public static void install(byte[] parameters, short offset, byte length) {
      Command.reader = new CBORApduReader();
      Command.writer = new CBORApduWriter();
      Command.hello = new Command() {
        @Override
        protected void run() {
          byte[] payload = new byte[600];
          Arrays.fill(payload, (byte) 0xA5);
          writer.bytes(payload);
        }
      };

      new WriterApplet().register();
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        Command.clearTransport();
        return;
      }

      if (apdu.getBuffer()[1] == 0x7E) {
        apdu.setOutgoing();
        Command.writer.send();
        return;
      }

      Command.process(apdu);
    }
  }

  public static class EmptyApplet extends Applet {

    public static void install(byte[] parameters, short offset, byte length) {
      new EmptyApplet().register();
    }

    @Override
    public void process(APDU apdu) {}
  }
}
