package monoidlib;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CBORApduWriterTest {

  private static final AID APPLET_AID = AIDUtil.create("f06d6f6e6f69647d01");

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    simulator = new CardSimulator();
    simulator.installApplet(APPLET_AID, WriterApplet.class);
    Assertions.assertTrue(simulator.selectApplet(APPLET_AID));
    simulator.changeProtocol("T=1");
  }

  @Test
  public void dynamicResponseBorrowsThenUsesPersistentChunks() {
    ResponseAPDU response = send(0x10, 769, 256);
    Assertions.assertEquals(256, response.getData().length);
    Assertions.assertEquals(0x6100, response.getSW());
    CBORApduWriter writer = WriterApplet.instance.dynamic;
    for (int index = 0; index < 4; index++) {
      Assertions.assertNotNull(writer.chunks[index]);
      Assertions.assertEquals(
        JCSystem.NOT_A_TRANSIENT_OBJECT,
        JCSystem.isTransient(writer.chunks[index])
      );
    }
    Assertions.assertNull(writer.chunks[4]);
    Assertions.assertArrayEquals(
      Arrays.copyOf(WriterApplet.instance.data, 769),
      collect(response, 256)
    );
    Assertions.assertFalse(writer.hasPending());
    for (Object chunk : writer.chunks) {
      Assertions.assertNull(chunk);
    }

    Assertions.assertArrayEquals(
      Arrays.copyOf(WriterApplet.instance.data, 200),
      send(0x10, 200, 256).getData()
    );
    Assertions.assertNull(writer.chunks[0]);
  }

  @Test
  public void fixedDirectResponseStoresBeforeGetResponseOverwritesTheAPDU() {
    Arrays.fill(WriterApplet.instance.response, (byte) 0x5A);
    ResponseAPDU response = send(0x11, 100, 17);
    Assertions.assertEquals(17, response.getData().length);
    Assertions.assertEquals(0x6154, response.getSW());
    Assertions.assertFalse(WriterApplet.instance.fixed.isDirect());
    Assertions.assertArrayEquals(withPrefix(100), collect(response, 17));
    Assertions.assertFalse(WriterApplet.instance.fixed.hasPending());
    Assertions.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED & 0xFFFF, next(17).getSW());
  }

  @Test
  public void fixedDirectSingleResponseLeavesPersistentBufferUntouched() {
    Arrays.fill(WriterApplet.instance.response, (byte) 0x5A);
    ResponseAPDU response = send(0x11, 100, 256);
    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertArrayEquals(withPrefix(100), response.getData());
    byte[] untouched = new byte[1024];
    Arrays.fill(untouched, (byte) 0x5A);
    Assertions.assertArrayEquals(untouched, WriterApplet.instance.response);
    Assertions.assertNull(WriterApplet.instance.fixed.chunks);
  }

  @Test
  public void fixedWindowResponseHonorsExtendedLeWithoutA256ByteCap() {
    ResponseAPDU response = send(0x12, 800, 1024);
    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertArrayEquals(withPrefix(800), response.getData());
  }

  @Test
  public void streamedResponseHonorsLeAndStopsAfterFourUnits() {
    ResponseAPDU response = send(0x13, 0, 17);
    Assertions.assertEquals(17, response.getData().length);
    Assertions.assertEquals(0x6100, response.getSW());
    Assertions.assertEquals(4, WriterApplet.instance.stream.units);
    Assertions.assertArrayEquals(
      Arrays.copyOf(WriterApplet.instance.data, 100),
      collect(response, 17)
    );
    Assertions.assertTrue(WriterApplet.instance.stream.reset);
    Assertions.assertFalse(WriterApplet.instance.dynamic.hasPending());
  }

  private byte[] withPrefix(int length) {
    byte[] result = new byte[length + 1];
    System.arraycopy(WriterApplet.instance.data, 0, result, 1, length);
    return result;
  }

  private ResponseAPDU send(int instruction, int length, int expected) {
    return simulator.transmitCommand(
      new CommandAPDU(0, instruction, length >> 8, length & 255, expected)
    );
  }

  private ResponseAPDU next(int expected) {
    return simulator.transmitCommand(new CommandAPDU(0, 0xC0, 0, 0, expected));
  }

  private byte[] collect(ResponseAPDU response, int expected) {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    for (short count = 0; ; count++) {
      Assertions.assertTrue(count < 100);
      result.writeBytes(response.getData());
      if (response.getSW() == 0x9000) {
        return result.toByteArray();
      }
      Assertions.assertEquals(0x6100, response.getSW() & 0xFF00);
      response = next(expected);
    }
  }

  public static class WriterApplet extends Applet implements ExtendedLength {

    static WriterApplet instance;

    final byte[] data = new byte[1024];
    final byte[] response = new byte[1024];
    final CBORApduWriter dynamic = new CBORApduWriter();
    final CBORApduWriter fixed = new CBORApduWriter(response, ISO7816.SW_FILE_FULL);
    StreamResponse stream;
    boolean fixedResponse;

    public static void install(byte[] data, short offset, byte length) {
      instance = new WriterApplet();
      instance.register();
    }

    WriterApplet() {
      for (short index = 0; index < data.length; index++) {
        data[index] = (byte) index;
      }
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        return;
      }
      byte[] buffer = apdu.getBuffer();
      byte instruction = buffer[ISO7816.OFFSET_INS];
      if (instruction == (byte) 0xC0) {
        if (fixedResponse) {
          fixed.send(apdu);
        } else {
          dynamic.send();
        }
        return;
      }
      short length = Util.getShort(buffer, ISO7816.OFFSET_P1);
      fixedResponse = instruction == 0x11 || instruction == 0x12;
      if (fixedResponse) {
        fixed.reset((short) 1, instruction == 0x11 ? (short) buffer.length : (short) 0);
        fixed.rawBytes(data, (short) 0, length);
        short responseLength = (short) (fixed.getLength() + 1);
        if (fixed.isDirect()) {
          buffer[0] = 0;
        } else {
          response[0] = 0;
        }
        fixed.send(apdu, responseLength);
      } else {
        if (instruction == 0x13) {
          stream = new StreamResponse(data);
          dynamic.start(stream, (short) 10);
        } else {
          dynamic.reset();
          dynamic.rawBytes(data, (short) 0, length);
        }
        dynamic.send();
      }
    }
  }

  private static class StreamResponse implements CBORResponse {

    private final byte[] data;
    short units;
    boolean reset;

    StreamResponse(byte[] data) {
      this.data = data;
    }

    @Override
    public boolean writeNext(CBORWriter writer) {
      writer.rawBytes(data, (short) (units * 10), (short) 10);
      return ++units < 10;
    }

    @Override
    public void reset() {
      reset = true;
    }
  }
}
