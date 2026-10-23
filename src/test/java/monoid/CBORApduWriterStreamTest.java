package monoid;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.JCSystem;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoidlib.CBORApduReader;
import monoidlib.CBORApduWriter;
import monoidlib.CBORResponse;
import monoidlib.CBORWriter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CBORApduWriterStreamTest {

  private static final String APPLET_AID = "f06d6f6e6f69647f03";

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");

    simulator = new CardSimulator();
    AID aid = AIDUtil.create(APPLET_AID);
    simulator.installApplet(aid, StreamApplet.class);
    Assertions.assertTrue(simulator.selectApplet(aid));
  }

  @Test
  public void sendsHeaderWhenSourceIsEmpty() {
    StreamResponse source = configure(0, 0);
    ResponseAPDU response = transmit(0x20);

    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertArrayEquals(new byte[] { (byte) 0x80 }, response.getData());
    Assertions.assertEquals(0, source.written);
    assertReleased(source);
  }

  @Test
  public void boundsGenerationPerAPDUForSmallItems() {
    StreamResponse source = configure(10, 1);
    ResponseAPDU response = transmit(0x20);

    Assertions.assertEquals(0x6100, response.getSW());
    Assertions.assertEquals(4, source.calls);
    Assertions.assertEquals(9, response.getData().length);
    Object window = writerField("window");
    Assertions.assertNotNull(window);
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(window));

    assertResponse(source, response, 256);
  }

  @Test
  public void preservesUnitsThatCrossPacketBoundaries() {
    StreamResponse source = configure(3, 130, 130, 11);
    ResponseAPDU response = transmit(0x20);

    Assertions.assertEquals(0x6100, response.getSW());
    Assertions.assertEquals(256, response.getData().length);
    Assertions.assertEquals(2, source.written);

    assertResponse(source, response, 256);
  }

  @Test
  public void sendsUnitLargerThanOnePacketAndReportsKnownRemainder() {
    StreamResponse source = configure(1, 600);
    ResponseAPDU first = transmit(0x20);

    Assertions.assertEquals(0x6100, first.getSW());
    Assertions.assertEquals(1, source.calls);

    ResponseAPDU second = transmit(0xC0);

    Assertions.assertEquals(0x615C, second.getSW());
    Assertions.assertEquals(1, source.calls);

    ResponseAPDU last = transmit(0xC0);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    for (ResponseAPDU response : new ResponseAPDU[] { first, second, last }) {
      output.write(response.getData(), 0, response.getData().length);
    }

    Assertions.assertEquals(0x9000, last.getSW());
    Assertions.assertArrayEquals(expected(source), output.toByteArray());
    assertReleased(source);
  }

  @Test
  public void finishesWhenLastUnitReturnsFalseAtExactPacketBoundary() {
    StreamResponse source = configure(1, 253);
    ResponseAPDU response = transmit(0x20);

    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertEquals(1, source.calls);
    Assertions.assertArrayEquals(expected(source), response.getData());
    assertReleased(source);
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());
    Assertions.assertEquals(1, source.resets);
  }

  @Test
  public void honorsShortLeWithoutLosingBufferedBytes() {
    StreamResponse source = configure(5, 130);

    assertResponse(source, transmit(0x20, 17), 17);
  }

  @Test
  public void streamsTotalResponseLargerThanSignedShort() {
    StreamResponse source = configure(700, 48);

    Assertions.assertTrue(expected(source).length > Short.MAX_VALUE);
    assertResponse(source, transmit(0x20), 256);
  }

  @Test
  public void releasesSourceOnceWhenNewCommandCancelsResponse() {
    StreamResponse source = configure(10, 1);

    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
    Assertions.assertEquals(0x6D00, transmit(0x7F).getSW());
    assertReleased(source);
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());
    Assertions.assertEquals(1, source.resets);
  }

  @Test
  public void releasesSourceOnDeselect() {
    StreamResponse source = configure(10, 1);

    Assertions.assertEquals(0x6100, transmit(0x20).getSW());

    AID other = AIDUtil.create("f06d6f6e6f69647f04");
    simulator.installApplet(other, EmptyApplet.class);
    Assertions.assertTrue(simulator.selectApplet(other));

    assertReleased(source);
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET_AID)));
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());
    Assertions.assertEquals(1, source.resets);
  }

  @Test
  public void releasesSourceAfterCardResetAndReselection() {
    StreamResponse source = configure(10, 1);

    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
    simulator.reset();
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET_AID)));

    assertReleased(source);
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());
    Assertions.assertEquals(1, source.resets);
  }

  @Test
  public void releasesSourceWhenContinuationCallbackFails() {
    StreamResponse source = configure(10, 1);
    source.failAt = 6;

    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
    Assertions.assertEquals(0x6F00, transmit(0xC0).getSW());
    assertReleased(source);
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());
    Assertions.assertEquals(1, source.resets);

    source = configure(1, 1);
    assertResponse(source, transmit(0x20), 256);
  }

  @Test
  public void releasesSourceWhenSendingFails() {
    StreamResponse source = configure(10, 1);

    Assertions.assertEquals(0x6100, transmit(0x20).getSW());
    Assertions.assertEquals(0x6F00, transmit(0x7E).getSW());
    assertReleased(source);
    Assertions.assertEquals(0x6985, transmit(0xC0).getSW());
    Assertions.assertEquals(1, source.resets);
  }

  private StreamResponse configure(int count, int... lengths) {
    StreamResponse source = new StreamResponse(count, lengths);
    StreamApplet.source = source;
    return source;
  }

  private ResponseAPDU transmit(int instruction) {
    return transmit(instruction, 256);
  }

  private ResponseAPDU transmit(int instruction, int le) {
    return new ResponseAPDU(
      simulator.transmitCommand(
        new CommandAPDU(0, instruction, 0, 0, new byte[] { (byte) 0xA0 }, le).getBytes()
      )
    );
  }

  private byte[] expected(StreamResponse source) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    writeLength(output, 0x80, source.count);

    for (int index = 0; index < source.count; index++) {
      int length = source.lengths[index % source.lengths.length];
      writeLength(output, 0x40, length);
      for (int offset = 0; offset < length; offset++) {
        output.write(index & 0xFF);
      }
    }

    return output.toByteArray();
  }

  private void writeLength(ByteArrayOutputStream output, int type, int length) {
    if (length < 24) {
      output.write(type | length);
    } else if (length <= 255) {
      output.write(type | 24);
      output.write(length);
    } else {
      output.write(type | 25);
      output.write(length >> 8);
      output.write(length);
    }
  }

  private void assertResponse(StreamResponse source, ResponseAPDU response, int le) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] expected = expected(source);
    int previousCalls = 0;

    while (true) {
      Assertions.assertTrue(source.calls - previousCalls <= 4);
      previousCalls = source.calls;
      Assertions.assertTrue(response.getData().length > 0);
      Assertions.assertTrue(response.getData().length <= le);
      output.write(response.getData(), 0, response.getData().length);

      if (response.getSW1() != 0x61) {
        break;
      }

      int remaining = expected.length - output.size();
      Assertions.assertEquals(
        source.written < source.count || remaining >= 256 ? 0x6100 : 0x6100 | remaining,
        response.getSW()
      );
      Assertions.assertTrue(output.size() < expected.length);
      response = transmit(0xC0, le);
    }

    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertArrayEquals(expected, output.toByteArray());
    assertReleased(source);
  }

  private void assertReleased(StreamResponse source) {
    Assertions.assertNull(writerField("window"));
    Assertions.assertNull(writerField("response"));
    Assertions.assertFalse(Command.writer.hasPending());
    Assertions.assertEquals(0, Command.writer.getLength());
    Assertions.assertEquals(1, source.resets);
  }

  private Object writerField(String name) {
    try {
      Field field = CBORApduWriter.class.getDeclaredField(name);
      field.setAccessible(true);
      return field.get(Command.writer);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }
  }

  private static class StreamResponse implements CBORResponse {

    final int count;
    final int[] lengths;
    final byte[] payload;

    int written;
    int calls;
    int resets;
    int failAt;

    StreamResponse(int count, int[] lengths) {
      this.count = count;
      this.lengths = lengths;

      int maxLength = 0;
      for (int length : lengths) {
        maxLength = Math.max(maxLength, length);
      }
      payload = new byte[maxLength];
    }

    @Override
    public boolean writeNext(CBORWriter writer) throws MonoidException {
      calls++;
      if (calls == failAt) {
        MonoidException.throwIt(MonoidException.CODE_NOT_FOUND);
      }

      if (written == count) {
        return false;
      }

      Arrays.fill(payload, (byte) written);
      writer.bytes(payload, (short) 0, (short) lengths[written % lengths.length]);
      written++;
      return written < count;
    }

    @Override
    public void reset() {
      resets++;
    }
  }

  public static class StreamApplet extends Applet {

    static StreamResponse source;

    private final ApduTransport transport = new ApduTransport(Command.reader, Command.writer);

    public static void install(byte[] parameters, short offset, byte length) {
      source = null;
      MonoidException.init();
      Command.reader = new CBORApduReader();
      Command.writer = new CBORApduWriter();
      Command.hello = new Command() {
        @Override
        protected void run() {
          writer.start(source, (short) (source.payload.length + 3));
          writer.array((short) source.count);
        }
      };

      new StreamApplet().register();
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        transport.clear();
        return;
      }

      if (apdu.getBuffer()[1] == 0x7E) {
        apdu.setOutgoing();
        Command.writer.send();
        return;
      }

      transport.process(apdu);
    }

    @Override
    public void deselect() {
      super.deselect();
      transport.clear();
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
