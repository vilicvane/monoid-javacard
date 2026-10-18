package monoid;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.JCSystem;
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
    Object firstChunk = Command.writer.chunks[0];

    Assertions.assertTrue(WriterApplet.ownedBufferBeforeSend);
    Assertions.assertNotNull(firstChunk);
    assertChunkCount(2);
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
  public void appendsChunksWithoutReplacingPreviouslyWrittenData() {
    byte[] expected = new byte[783];
    expected[0] = (byte) 0x99;
    expected[1] = 0x03;
    expected[2] = 0x0C;
    for (int index = 0; index < 780; index++) {
      expected[index + 3] = (byte) (index % 2 == 0 ? 0xF4 : 0xF5);
    }

    ResponseAPDU response = transmit(0x20, 7);

    assertChunkCount(4);
    Assertions.assertNull(WriterApplet.firstChunks[2]);
    Assertions.assertNull(WriterApplet.secondChunks[3]);
    for (int index = 0; index < 2; index++) {
      Assertions.assertSame(WriterApplet.firstChunks[index], Command.writer.chunks[index]);
    }
    for (int index = 0; index < 3; index++) {
      Assertions.assertSame(WriterApplet.secondChunks[index], Command.writer.chunks[index]);
    }
    for (int index = 0; index < 4; index++) {
      Assertions.assertSame(WriterApplet.thirdChunks[index], Command.writer.chunks[index]);
    }

    assertResponse(expected, response);
  }

  @Test
  public void writesByteStringAcrossMultipleChunksInOneCall() {
    ResponseAPDU response = transmit(0x20, 8);

    assertChunkCount(4);
    assertResponse(byteString(900), response);
  }

  @Test
  public void allocatesPersistentChunksOnlyAboveTransientLimit() {
    Assertions.assertEquals(
      JCSystem.NOT_A_TRANSIENT_OBJECT,
      JCSystem.isTransient(Command.writer.chunks)
    );

    ResponseAPDU response = transmit(0x20, 9);
    assertChunkCount(2);
    assertResponse(byteString(509), response);

    response = transmit(0x20, 11);
    assertChunkCount(3);
    assertResponse(byteString(510), response);
  }

  @Test
  public void keepsPlainBufferWriterChunksTransient() {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.bytes(new byte[600]);

    for (int index = 0; index < 3; index++) {
      Assertions.assertEquals(
        JCSystem.CLEAR_ON_DESELECT,
        JCSystem.isTransient(writer.chunks[index])
      );
    }
  }

  @Test
  public void sendsResponsesEndingAtExactChunkBoundaries() {
    for (int mode : new int[] { 9, 10 }) {
      byte[] expected = byteString(mode == 9 ? 509 : 765);
      ResponseAPDU response = transmit(0x20, mode);

      assertChunkCount(mode == 9 ? 2 : 3);
      for (int offset = 0; offset < expected.length; offset += 256) {
        Assertions.assertEquals(
          offset + 256 == expected.length ? 0x9000 : 0x6100,
          response.getSW()
        );
        Assertions.assertArrayEquals(
          Arrays.copyOfRange(expected, offset, offset + 256),
          response.getData()
        );
        if (offset + 256 < expected.length) {
          response = transmit(0xC0);
        }
      }

      assertReleased();
      Assertions.assertEquals(0x6985, transmit(0xC0).getSW());
    }
  }

  @Test
  public void copyHelpersReadBothBorrowedAndOwnedBuffers() {
    for (int mode : new int[] { 5, 6 }) {
      byte[] expected = byteString(mode == 5 ? 32 : 900);
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
    Object firstChunk = Command.writer.chunks[0];
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
    Assertions.assertSame(firstChunk, Command.writer.chunks[0]);

    ResponseAPDU last = transmit(0xC0);

    Assertions.assertEquals(0x9000, last.getSW());
    Assertions.assertArrayEquals(Arrays.copyOfRange(expected, 512, 603), last.getData());
    assertReleased();
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());

    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
    Assertions.assertNotSame(firstChunk, Command.writer.chunks[0]);
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
  public void releasesPersistentChunksAfterReset() {
    Assertions.assertEquals(0x6100, transmit(0x20, 8).getSW());
    assertChunkCount(4);
    Object persistentChunk = Command.writer.chunks[2];

    simulator.reset();

    Assertions.assertSame(persistentChunk, Command.writer.chunks[2]);
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create("f06d6f6e6f69647f01")));

    assertReleased();
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());
    assertResponse(byteString(900), transmit(0x20, 8));
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
    assertChunkCount(0);
    Assertions.assertEquals(0, Command.writer.getLength());
    Assertions.assertFalse(Command.writer.hasPending());
  }

  private void assertChunkCount(int count) {
    for (int index = 0; index < Command.writer.chunks.length; index++) {
      if (index < count) {
        Assertions.assertNotNull(Command.writer.chunks[index]);
        Assertions.assertEquals(256, ((byte[]) Command.writer.chunks[index]).length);
        Assertions.assertEquals(
          index < 2 ? JCSystem.CLEAR_ON_DESELECT : JCSystem.NOT_A_TRANSIENT_OBJECT,
          JCSystem.isTransient(Command.writer.chunks[index])
        );
      } else {
        Assertions.assertNull(Command.writer.chunks[index]);
      }
    }
  }

  private void assertResponse(byte[] expected, ResponseAPDU response) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    while (true) {
      output.write(response.getData(), 0, response.getData().length);
      if (response.getSW1() != 0x61) {
        break;
      }
      response = transmit(0xC0);
    }

    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertArrayEquals(expected, output.toByteArray());
    assertReleased();
  }

  public static class WriterApplet extends MonoidApplet {

    static boolean ownedBufferBeforeSend;
    static boolean borrowedBeforeLastByte;
    static byte[] copied;
    static byte[] snapshot;
    static short copyLength;
    static Object[] firstChunks;
    static Object[] secondChunks;
    static Object[] thirdChunks;

    public static void install(byte[] parameters, short offset, byte length) {
      ownedBufferBeforeSend = false;
      borrowedBeforeLastByte = false;
      copied = null;
      snapshot = null;
      copyLength = 0;
      firstChunks = null;
      secondChunks = null;
      thirdChunks = null;
      Command.reader = new CBORApduReader();
      Command.writer = new CBORApduWriter();
      Command.hello = new Command() {
        @Override
        protected void run() {
          byte mode = APDU.getCurrentAPDUBuffer()[2];

          if (mode == 4 || mode == 7) {
            short length = mode == 4 ? (short) 255 : (short) 780;
            writer.array(length);
            for (short index = 0; index < length; index++) {
              if (mode == 4 && index == 254) {
                borrowedBeforeLastByte = writer.chunks[0] == null;
              }
              writer.bool(index % 2 != 0);

              if (mode == 7) {
                switch (writer.getLength()) {
                  case 257:
                    firstChunks = Arrays.copyOf(writer.chunks, 4);
                    break;
                  case 513:
                    secondChunks = Arrays.copyOf(writer.chunks, 4);
                    break;
                  case 769:
                    thirdChunks = Arrays.copyOf(writer.chunks, 4);
                    break;
                }
              }
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
              case 8:
                length = 900;
                break;
              case 9:
                length = 509;
                break;
              case 10:
                length = 765;
                break;
              case 11:
                length = 510;
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

          ownedBufferBeforeSend = writer.chunks[0] != null;
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
