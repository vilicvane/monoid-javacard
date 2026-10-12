package monoid;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.JCSystem;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CBORApduReaderTest {

  private static final AID READER_AID = AIDUtil.create("f06d6f6e6f69647f01");

  private static CBORApduReader installedReader;

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");

    simulator = new CardSimulator();
    simulator.installApplet(READER_AID, ReaderApplet.class);
    Assertions.assertTrue(simulator.selectApplet(READER_AID));
  }

  @Test
  public void receivesShortRequestsThroughMaximumLength() {
    assertEcho((short) 3);
    assertEcho((short) 253);
  }

  @Test
  public void rejectsEmptyRequestThenAcceptsRetry() {
    ResponseAPDU response = new ResponseAPDU(
      simulator.transmitCommand(new CommandAPDU(0, 1, 0, 0).getBytes())
    );
    Assertions.assertEquals(0x6700, response.getSW());

    assertEcho((short) 3);
  }

  @Test
  public void keepsRequestInChunksAndClearsThemAfterUse() throws Exception {
    assertEcho((short) 1167);
    assertReleased(new Object[0]);
    assertEcho((short) 3);
  }

  @Test
  public void allocatesPersistentChunksOnlyAboveTransientLimit() throws Exception {
    Object[] chunks = chunks();
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(chunks));
    assertReleased(new Object[0]);

    beginRequest(512);
    assertChunkTypes(2);

    Assertions.assertEquals(0x9000, transmit(0xB0, 1, new byte[] { (byte) 0xA5 }).getSW());
    assertChunkTypes(3);

    Assertions.assertEquals(0x9000, transmit(0xB0, 1, new byte[255]).getSW());
    Assertions.assertEquals(0x9000, transmit(0xB0, 1, new byte[] { (byte) 0xA5 }).getSW());
    assertChunkTypes(4);
  }

  @Test
  public void erasesPersistentChunksWhenRequestIsReplacedOrRejected() throws Exception {
    for (int operation = 0; operation < 4; operation++) {
      beginRequest(513);
      Object[] allocated = chunks().clone();

      if (operation == 0) {
        assertEcho((short) 3);
      } else if (operation == 1) {
        beginRequest(1);
      } else if (operation == 2) {
        Assertions.assertEquals(0x6883, transmit(0xB0, 2, new byte[] { 0 }).getSW());
      } else {
        Assertions.assertEquals(0x6A80, transmit(0xA0, 1, new byte[] { 0 }).getSW());
      }

      if (operation == 1) {
        assertErased(allocated);
      } else {
        assertReleased(allocated);
      }
    }

    assertEcho((short) 3);
  }

  @Test
  public void erasesPersistentChunksOnDeselect() throws Exception {
    beginRequest(513);
    Object[] allocated = chunks().clone();
    AID other = AIDUtil.create("f06d6f6e6f69647f02");
    simulator.installApplet(other, EmptyApplet.class);

    Assertions.assertTrue(simulator.selectApplet(other));

    assertReleased(allocated);
    Assertions.assertTrue(simulator.selectApplet(READER_AID));
    Assertions.assertEquals(0x6883, transmit(0xA0, 1, new byte[] { 0 }).getSW());
    assertEcho((short) 3);
  }

  @Test
  public void erasesPersistentChunksAfterResetClearsTransientState() throws Exception {
    beginRequest(769);
    Object[] allocated = chunks().clone();

    simulator.reset();

    Assertions.assertFalse(installedReader.isReceiving());
    Assertions.assertEquals(0, installedReader.getLength());
    Assertions.assertSame(allocated[2], chunks()[2]);
    Assertions.assertEquals((byte) 0xA5, ((byte[]) allocated[2])[0]);
    Assertions.assertTrue(simulator.selectApplet(READER_AID));

    assertReleased(allocated);
    Assertions.assertEquals(0x6883, transmit(0xA0, 1, new byte[] { 0 }).getSW());
    assertEcho((short) 3);
  }

  @Test
  public void receivesManySmallFramesIntoReusableChunks() {
    assertEcho((short) 1167, 1);
    assertEcho((short) 8189, 17);
  }

  @Test
  public void readsKeysLengthHeadersAndSmallValuesAcrossChunks() {
    for (int paddingLength : new int[] { 227, 240, 243 }) {
      CBORBufferWriter writer = new CBORBufferWriter();
      writer.map((short) 5);
      writer.text("pad".getBytes());
      writer.bytes(new byte[paddingLength]);
      writer.text("message".getBytes());
      writer.bytes(payload((short) 512));
      writer.text("label".getBytes());
      writer.text("testing".getBytes());
      writer.text("number".getBytes());
      writer.integer((short) 257);
      writer.text("enabled".getBytes());
      writer.bool(true);

      assertRequest(writer.getDataBuffer(), (short) 512, 17, 2);
    }
  }

  private void assertEcho(short length) {
    assertEcho(length, 255);
  }

  private void beginRequest(int length) {
    for (int offset = 0; offset < length; offset += 255) {
      byte[] data = new byte[Math.min(255, length - offset)];
      Arrays.fill(data, (byte) 0xA5);
      ResponseAPDU response = transmit(offset == 0 ? 0x90 : 0xB0, 1, data);
      Assertions.assertEquals(0x9000, response.getSW());
      Assertions.assertEquals(0, response.getData().length);
    }
  }

  private ResponseAPDU transmit(int cla, int instruction, byte[] data) {
    return new ResponseAPDU(
      simulator.transmitCommand(new CommandAPDU(cla, instruction, 0, 0, data).getBytes())
    );
  }

  private Object[] chunks() throws Exception {
    Field field = CBORApduReader.class.getDeclaredField("chunks");
    field.setAccessible(true);
    return (Object[]) field.get(installedReader);
  }

  private void assertChunkTypes(int allocated) throws Exception {
    Object[] chunks = chunks();

    for (int index = 0; index < chunks.length; index++) {
      if (index >= allocated) {
        Assertions.assertNull(chunks[index]);
        continue;
      }

      Assertions.assertEquals(256, ((byte[]) chunks[index]).length);
      Assertions.assertEquals(
        index < 2 ? JCSystem.CLEAR_ON_DESELECT : JCSystem.NOT_A_TRANSIENT_OBJECT,
        JCSystem.isTransient(chunks[index])
      );
    }
  }

  private void assertErased(Object[] allocated) {
    for (Object chunk : allocated) {
      if (chunk != null) {
        Assertions.assertArrayEquals(new byte[256], (byte[]) chunk);
      }
    }
  }

  private void assertReleased(Object[] allocated) throws Exception {
    assertErased(allocated);

    for (Object chunk : chunks()) {
      Assertions.assertNull(chunk);
    }
  }

  private void assertEcho(short length, int frameLength) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.bytes(payload(length));

    assertRequest(writer.getDataBuffer(), length, frameLength, 1);
  }

  private static byte[] payload(short length) {
    byte[] result = new byte[length];

    for (short index = 0; index < length; index++) {
      result[index] = (byte) index;
    }

    return result;
  }

  private void assertRequest(byte[] request, short length, int frameLength, int instruction) {
    for (int offset = 0; offset < request.length; offset += frameLength) {
      int end = Math.min(offset + frameLength, request.length);
      boolean last = end == request.length;
      int cla = offset == 0 ? (last ? 0x00 : 0x90) : (last ? 0xA0 : 0xB0);
      ResponseAPDU response = new ResponseAPDU(
        simulator.transmitCommand(
          new CommandAPDU(
            cla,
            instruction,
            0,
            0,
            Arrays.copyOfRange(request, offset, end)
          ).getBytes()
        )
      );
      Assertions.assertEquals(0x9000, response.getSW());
      Assertions.assertArrayEquals(
        last ? payload((short) Math.min(length, 256)) : new byte[0],
        response.getData()
      );
    }
  }

  public static class ReaderApplet extends Applet {

    private final CBORApduReader reader = new CBORApduReader();

    public static void install(byte[] parameters, short offset, byte length) {
      ReaderApplet applet = new ReaderApplet();
      installedReader = applet.reader;
      applet.register();
    }

    @Override
    public void deselect() {
      super.deselect();
      reader.clear();
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        reader.clear();
        return;
      }

      boolean pending = false;
      List<byte[]> chunks = new ArrayList<>();

      try {
        pending = !reader.receive();

        if (pending) {
          return;
        }

        Assertions.assertEquals(APDU.STATE_FULL_INCOMING, apdu.getCurrentState());
        reader.reset();

        if (apdu.getBuffer()[0] == 0) {
          Assertions.assertSame(apdu.getBuffer(), reader.getChunk((short) 0));
        }

        for (short position = 0; position < reader.getLength(); ) {
          byte[] chunk = reader.getChunk(position);
          short available = reader.getChunkLength(position);
          Assertions.assertTrue(available > 0);
          Assertions.assertTrue(available <= reader.getLength() - position);
          Assertions.assertTrue(reader.getChunkOffset(position) + available <= chunk.length);
          chunks.add(chunk);
          position += available;
        }

        if (apdu.getBuffer()[1] == 2) {
          Assertions.assertEquals(5, reader.map());
          Assertions.assertArrayEquals(
            "testing".getBytes(),
            reader.requireKey("label".getBytes()).text()
          );
          Assertions.assertEquals(257, reader.requireKey("number".getBytes()).integer());
          Assertions.assertTrue(reader.requireKey("enabled".getBytes()).bool());
          Assertions.assertFalse(reader.key("missing".getBytes()));
          byte[] copiedMessage = new byte[518];
          Arrays.fill(copiedMessage, (byte) 0xA5);
          Assertions.assertEquals(
            512,
            reader.requireKey("message".getBytes()).bytes(copiedMessage, (short) 3)
          );
          Assertions.assertArrayEquals(
            payload((short) 512),
            Arrays.copyOfRange(copiedMessage, 3, 515)
          );
          Assertions.assertEquals((byte) 0xA5, copiedMessage[2]);
          Assertions.assertEquals((byte) 0xA5, copiedMessage[515]);
          reader.requireKey("message".getBytes());
        }

        short length = reader.bytesLength();
        short offset = reader.getOffset();

        for (short index = 0; index < length; index++) {
          short position = (short) (offset + index);
          Assertions.assertEquals(
            (byte) index,
            reader.getChunk(position)[reader.getChunkOffset(position)]
          );
        }

        short responseLength = (short) Math.min(length, 256);
        byte[] response = new byte[responseLength];

        for (short index = 0; index < responseLength; index++) {
          short position = (short) (offset + index);
          response[index] = reader.getChunk(position)[reader.getChunkOffset(position)];
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength(responseLength);
        apdu.sendBytesLong(response, (short) 0, responseLength);
      } finally {
        if (!pending) {
          reader.clear();

          for (byte[] chunk : chunks) {
            if (chunk != apdu.getBuffer()) {
              Assertions.assertArrayEquals(new byte[chunk.length], chunk);
            }
          }
        }
      }
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
