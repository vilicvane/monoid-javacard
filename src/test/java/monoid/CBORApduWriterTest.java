package monoid;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
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
  public void borrowsAPDUBufferForSingleResponse() {
    for (int mode : new int[] { 1, 2 }) {
      ResponseAPDU response = transmit(0x20, mode);

      Assertions.assertEquals(0x9000, response.getSW());
      Assertions.assertArrayEquals(byteString(mode == 1 ? 32 : 254), response.getData());
      Assertions.assertFalse(WriterApplet.ownedBufferBeforeSend);
      assertReleased();
    }
  }

  @Test
  public void promotesByteStringToOwnedBufferBeforeSendingFragments() {
    byte[] expected = byteString(255);
    ResponseAPDU first = transmit(0x20, 3);
    byte[] buffer = Command.writer.buffer;

    Assertions.assertTrue(WriterApplet.ownedBufferBeforeSend);
    Assertions.assertNotNull(buffer);
    Assertions.assertEquals(0x6101, first.getSW());
    Assertions.assertArrayEquals(Arrays.copyOfRange(expected, 0, 256), first.getData());

    ResponseAPDU last = transmit(0xC0);

    Assertions.assertEquals(0x9000, last.getSW());
    Assertions.assertArrayEquals(Arrays.copyOfRange(expected, 256, 257), last.getData());
    assertReleased();
  }

  @Test
  public void promotesAtSingleByteBoundaryWithTheWrittenPrefixIntact() {
    byte[] expected = new byte[257];
    expected[0] = (byte) 0x98;
    expected[1] = (byte) 0xFF;
    for (int index = 0; index < 255; index++) {
      expected[index + 2] = (byte) (index % 2 == 0 ? 0xF4 : 0xF5);
    }

    ResponseAPDU first = transmit(0x20, 4);

    Assertions.assertTrue(WriterApplet.borrowedBeforeLastByte);
    Assertions.assertTrue(WriterApplet.ownedBufferBeforeSend);
    Assertions.assertEquals(0x6101, first.getSW());
    Assertions.assertArrayEquals(Arrays.copyOfRange(expected, 0, 256), first.getData());

    ResponseAPDU last = transmit(0xC0);

    Assertions.assertEquals(0x9000, last.getSW());
    Assertions.assertArrayEquals(Arrays.copyOfRange(expected, 256, 257), last.getData());
    assertReleased();
  }

  @Test
  public void copyHelpersReadBothBorrowedAndOwnedBuffers() {
    for (int mode : new int[] { 5, 6 }) {
      byte[] expected = byteString(mode == 5 ? 32 : 300);
      ResponseAPDU response = transmit(0x20, mode);
      ByteArrayOutputStream output = new ByteArrayOutputStream();

      while (true) {
        output.write(response.getData(), 0, response.getData().length);
        if (response.getSW1() != 0x61) {
          break;
        }
        response = transmit(0xC0);
      }

      Assertions.assertEquals(0x9000, response.getSW());
      Assertions.assertEquals(mode == 6, WriterApplet.ownedBufferBeforeSend);
      Assertions.assertArrayEquals(expected, output.toByteArray());
      Assertions.assertArrayEquals(expected, WriterApplet.snapshot);
      Assertions.assertEquals(expected.length, WriterApplet.copyLength);
      byte[] copied = new byte[expected.length + 4];
      Arrays.fill(copied, (byte) 0x7E);
      System.arraycopy(expected, 0, copied, 2, expected.length);
      Assertions.assertArrayEquals(copied, WriterApplet.copied);
      assertReleased();
    }
  }

  @Test
  public void releasesBorrowedResponseWhenSendFails() {
    Assertions.assertEquals(0x6F00, transmit(0x7D).getSW());
    assertReleased();
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());
    Assertions.assertEquals(0x9000, transmit(0x20, 1).getSW());
    Assertions.assertFalse(WriterApplet.ownedBufferBeforeSend);
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

    ResponseAPDU second = transmit(0xC0);

    Assertions.assertEquals(0x615B, second.getSW());
    Assertions.assertArrayEquals(Arrays.copyOfRange(expected, 256, 512), second.getData());
    Assertions.assertSame(buffer, Command.writer.buffer);

    ResponseAPDU last = transmit(0xC0);

    Assertions.assertEquals(0x9000, last.getSW());
    Assertions.assertArrayEquals(Arrays.copyOfRange(expected, 512, 603), last.getData());
    assertReleased();
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());

    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
    Assertions.assertNotSame(buffer, Command.writer.buffer);
  }

  @Test
  public void releasesCancelledResponseBeforeNewCommand() {
    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
    Assertions.assertEquals(0x6D00, transmit(0x7F).getSW());

    assertReleased();
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());
    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
  }

  @Test
  public void releasesPendingResponseOnDeselect() {
    Assertions.assertEquals(0x6100, transmit(0x20).getSW());

    AID other = AIDUtil.create("f06d6f6e6f69647f02");
    simulator.installApplet(other, EmptyApplet.class);

    Assertions.assertTrue(simulator.selectApplet(other));

    assertReleased();
  }

  @Test
  public void releasesResponseWhenSendFails() {
    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
    Assertions.assertEquals(0x6F00, transmit(0x7E).getSW());

    assertReleased();
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());
    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
  }

  private ResponseAPDU transmit(int instruction) {
    return transmit(instruction, 0);
  }

  private ResponseAPDU transmit(int instruction, int mode) {
    return new ResponseAPDU(
      simulator.transmitCommand(
        new CommandAPDU(0, instruction, mode, 0, new byte[] { (byte) 0xA0 }).getBytes()
      )
    );
  }

  private byte[] byteString(int length) {
    int headerLength = length <= 255 ? 2 : 3;
    byte[] expected = new byte[length + headerLength];
    expected[0] = (byte) (headerLength == 2 ? 0x58 : 0x59);
    if (headerLength == 3) {
      expected[1] = (byte) (length >> 8);
    }
    expected[headerLength - 1] = (byte) length;
    Arrays.fill(expected, headerLength, expected.length, (byte) 0xA5);
    return expected;
  }

  private void assertReleased() {
    Assertions.assertNull(Command.writer.buffer);
    Assertions.assertEquals(0, Command.writer.getLength());
    Assertions.assertFalse(Command.writer.hasPending());
  }

  public static class WriterApplet extends MonoidApplet {

    static boolean ownedBufferBeforeSend;
    static boolean borrowedBeforeLastByte;
    static byte[] copied;
    static byte[] snapshot;
    static short copyLength;

    public static void install(byte[] parameters, short offset, byte length) {
      ownedBufferBeforeSend = false;
      borrowedBeforeLastByte = false;
      copied = null;
      snapshot = null;
      copyLength = 0;
      Command.reader = new CBORApduReader();
      Command.writer = new CBORApduWriter();
      Command.hello = new Command() {
        @Override
        protected void run() {
          byte mode = APDU.getCurrentAPDUBuffer()[2];

          if (mode == 4) {
            writer.array((short) 255);
            for (short index = 0; index < 255; index++) {
              if (index == 254) {
                borrowedBeforeLastByte = writer.buffer == null;
              }
              writer.bool(index % 2 != 0);
            }
          } else {
            short length;
            switch (mode) {
              case 1:
              case 5:
                length = 32;
                break;
              case 2:
                length = 254;
                break;
              case 3:
                length = 255;
                break;
              case 6:
                length = 300;
                break;
              default:
                length = 600;
                break;
            }
            byte[] payload = new byte[length];
            Arrays.fill(payload, (byte) 0xA5);
            writer.bytes(payload);
          }

          if (mode == 5 || mode == 6) {
            copied = new byte[writer.getLength() + 4];
            Arrays.fill(copied, (byte) 0x7E);
            copyLength = writer.copyDataTo(copied, (short) 2);
            snapshot = writer.getDataBuffer();
          }

          ownedBufferBeforeSend = writer.buffer != null;
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

      if (apdu.getBuffer()[1] == 0x7D) {
        Command.writer.reset();
        Command.writer.bool(true);
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
