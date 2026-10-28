package monoid;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.Util;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoididentity.MonoidIdentityApplet;
import monoidlib.CBORApduReader;
import monoidlib.CBORApduWriter;
import monoidlib.CBORBufferReader;
import monoidlib.CBORResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SafeDataResponseTest {

  private static final AID IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_IDENTITY_AID}}"
    "f06d6f6e6f69640001"
  );

  private static final AID APPLET_AID = AIDUtil.create("f06d6f6e6f69647f05");

  private static TrackingWriter writer;
  private static TrackingResponse response;
  private static TestData source;

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    simulator = new CardSimulator(new ShareableSimulatorRuntime());
    simulator.installApplet(IDENTITY_AID, MonoidIdentityApplet.class);
    simulator.installApplet(APPLET_AID, ResponseApplet.class);
    Assertions.assertTrue(simulator.selectApplet(APPLET_AID));
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(APPLET_AID);
    Command.dispose();
    MonoidException.dispose();
    writer = null;
    response = null;
    source = null;
  }

  @Test
  public void copiesTinyDataDirectlyAfterTheHeaderAndReleasesTheSource() {
    source = new TestData(32);

    assertData(transmit(0x20));
    Assertions.assertEquals(0, writer.streams);
    Assertions.assertEquals(1, source.reads);
    Assertions.assertEquals(8, source.bufferOffset);
    assertReleased();
  }

  @Test
  public void releasesAnEmptySourceWithoutAllocatingAStreamOrReadingData() {
    source = new TestData(0);

    assertData(transmit(0x20));
    Assertions.assertEquals(0, writer.streams);
    Assertions.assertEquals(0, source.reads);
    assertReleased();
  }

  @Test
  public void usesTheBorrowedBufferThroughTheExactPacketBoundary() {
    source = new TestData(248);
    ResponseAPDU result = transmit(0x20);

    Assertions.assertEquals(256, result.getData().length);
    assertData(result);
    Assertions.assertEquals(0, writer.streams);
    assertReleased();
  }

  @Test
  public void streamsWhenTheEncodedResponseExceedsOnePacket() {
    source = new TestData(249);
    ResponseAPDU first = transmit(0x20);
    ResponseAPDU last = transmit(0xC0);

    Assertions.assertEquals(0x6101, first.getSW());
    Assertions.assertEquals(0x9000, last.getSW());
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    output.write(first.getData(), 0, first.getData().length);
    output.write(last.getData(), 0, last.getData().length);
    assertData(output.toByteArray());
    Assertions.assertEquals(1, writer.streams);
    Assertions.assertEquals(0, source.bufferOffset);
    assertReleased();
  }

  @Test
  public void releasesTheSmallSourceWhenItsReadFails() {
    source = new TestData(32);
    source.fail = true;
    ResponseAPDU result = transmit(0x20);

    Assertions.assertEquals(0x9000, result.getSW());
    CBORBufferReader reader = new CBORBufferReader(result.getData());
    reader.map();
    reader.requireKey(Text.error).map();
    Assertions.assertArrayEquals(
      MonoidException.CODE_NOT_FOUND,
      reader.requireKey(Text.code).text()
    );
    Assertions.assertEquals(0, writer.streams);
    assertReleased();
  }

  private ResponseAPDU transmit(int instruction) {
    return simulator.transmitCommand(
      new CommandAPDU(0, instruction, 0, 0, new byte[] { (byte) 0xA0 }, 256)
    );
  }

  private void assertData(ResponseAPDU result) {
    Assertions.assertEquals(0x9000, result.getSW());
    assertData(result.getData());
  }

  private void assertData(byte[] data) {
    CBORBufferReader reader = new CBORBufferReader(data);
    reader.map();
    Assertions.assertArrayEquals(source.data, reader.requireKey(Text.data).bytes());
  }

  private void assertReleased() {
    Assertions.assertFalse(writer.hasPending());
    Assertions.assertFalse(response.writeNext(writer));
    Assertions.assertEquals(1, response.resets);
  }

  private static class TrackingWriter extends CBORApduWriter {

    int streams;

    @Override
    public void start(CBORResponse response, short maxUnitLength) {
      streams++;
      super.start(response, maxUnitLength);
    }
  }

  private static class TrackingResponse extends SafeDataResponse {

    int resets;

    @Override
    public void reset() {
      resets++;
      super.reset();
    }
  }

  private static class TestData extends SafeDataSource {

    final byte[] data;
    int reads;
    short bufferOffset;
    boolean fail;

    TestData(int length) {
      data = new byte[length];

      for (int index = 0; index < length; index++) {
        data[index] = (byte) index;
      }
    }

    @Override
    public short getLength() {
      return (short) data.length;
    }

    @Override
    public void read(short dataOffset, byte[] buffer, short offset, short length) {
      reads++;
      bufferOffset = offset;

      if (fail) {
        MonoidException.throwIt(MonoidException.CODE_NOT_FOUND);
      }

      Util.arrayCopyNonAtomic(data, dataOffset, buffer, offset, length);
    }
  }

  public static class ResponseApplet extends Applet {

    private final ApduTransport transport = new ApduTransport(Command.reader, Command.writer);

    public static void install(byte[] parameters, short offset, byte length) {
      MonoidApplet.safe = new Safe();
      MonoidApplet.keystore = null;

      MonoidException.init();
      Command.reader = new CBORApduReader();
      writer = new TrackingWriter();
      Command.writer = writer;
      response = new TrackingResponse();
      Command.hello = new Command() {
        @Override
        protected void run() {
          short length = response.start(writer, source, (short) (2 + Text.data.length));
          writer.map((short) 1);
          writer.text(Text.data);
          writer.bytesLength(length);
          response.writeData(writer);
        }
      };
      new ResponseApplet().register();
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
      super.deselect();
      transport.clear();
    }
  }
}
