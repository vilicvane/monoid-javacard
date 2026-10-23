package monoidlib;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacardx.apdu.ExtendedLength;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CBORApduReaderTest {

  private static final AID READER_AID = AIDUtil.create("f06d6f6e6f69647f01");
  private static final AID OTHER_AID = AIDUtil.create("f06d6f6e6f69647f02");

  private static CBORApduReader installedReader;

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    simulator = new CardSimulator();
    simulator.installApplet(READER_AID, ReaderApplet.class);
    Assertions.assertTrue(simulator.selectApplet(READER_AID));
  }

  @Test
  public void assemblesShortFramesInOnePersistentBuffer() {
    byte[] buffer = installedReader.getBuffer();
    byte[] request = payload(1200);
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(buffer));

    for (int offset = 0; offset < request.length; offset += 255) {
      int end = Math.min(offset + 255, request.length);
      Assertions.assertEquals(
        0x9000,
        transmit(offset == 0 ? 1 : 2, Arrays.copyOfRange(request, offset, end)).getSW()
      );
      Assertions.assertEquals(end, installedReader.getReceivedLength());
    }

    assertRequest(request);
    Assertions.assertSame(buffer, installedReader.getBuffer());
    installedReader.clear();
    Assertions.assertEquals(0, installedReader.getReceivedLength());
    Assertions.assertSame(buffer, installedReader.getBuffer());
  }

  @Test
  public void receivesExtendedInputWithoutAssemblingAnotherBuffer() {
    simulator.changeProtocol("T=1");
    for (int length : new int[] { 600, 1200 }) {
      byte[] request = payload(length);
      Assertions.assertEquals(0x9000, transmit(1, request).getSW());
      assertRequest(request);
    }
  }

  @Test
  public void rejectsCumulativeOverflowAndAcceptsTheNextRequest() {
    simulator.changeProtocol("T=1");
    Assertions.assertEquals(0x9000, transmit(1, payload(1200)).getSW());
    Assertions.assertEquals(0x6700, transmit(2, new byte[] { 1 }).getSW());
    Assertions.assertEquals(0, installedReader.getReceivedLength());
    byte[] request = new byte[] { 2, (byte) 0xA1, 1, (byte) 0xF5 };
    Assertions.assertEquals(0x9000, transmit(1, request).getSW());
    assertRequest(request);

    installedReader.reset((short) 1, (short) (request.length - 1));
    Assertions.assertEquals(request.length, installedReader.getReceivedLength());
    CBORMap map = installedReader.map(new short[] { 1 });
    Assertions.assertTrue(map.requireKey((short) 1).bool());
    Assertions.assertTrue(installedReader.atEnd());
    short offset = installedReader.getOffset();
    installedReader.clear();
    Assertions.assertEquals(offset, installedReader.getOffset());
    Assertions.assertEquals(0, installedReader.getReceivedLength());
  }

  @Test
  public void clearsInputBoundsOnDeselectAndResetButRetainsTheBuffer() {
    simulator.installApplet(OTHER_AID, EmptyApplet.class);
    byte[] buffer = installedReader.getBuffer();
    for (boolean reset : new boolean[] { false, true }) {
      Assertions.assertEquals(0x9000, transmit(1, payload(255)).getSW());
      if (reset) {
        simulator.reset();
      } else {
        Assertions.assertTrue(simulator.selectApplet(OTHER_AID));
      }
      Assertions.assertEquals(0, installedReader.getReceivedLength());
      Assertions.assertSame(buffer, installedReader.getBuffer());
      Assertions.assertTrue(simulator.selectApplet(READER_AID));
      byte[] request = new byte[] { 1, 2, 3 };
      Assertions.assertEquals(0x9000, transmit(1, request).getSW());
      assertRequest(request);
    }
  }

  private void assertRequest(byte[] expected) {
    Assertions.assertEquals(expected.length, installedReader.getReceivedLength());
    Assertions.assertFalse(installedReader.hasChunks());
    Assertions.assertArrayEquals(
      expected,
      Arrays.copyOf(installedReader.getBuffer(), installedReader.getReceivedLength())
    );
    Assertions.assertSame(installedReader.getBuffer(), installedReader.getChunk((short) 1));
    Assertions.assertEquals(1, installedReader.getChunkOffset((short) 1));
    Assertions.assertEquals(expected.length - 1, installedReader.getChunkLength((short) 1));
  }

  private ResponseAPDU transmit(int instruction, byte[] data) {
    return simulator.transmitCommand(new CommandAPDU(0x80, instruction, 0, 0, data));
  }

  private static byte[] payload(int length) {
    byte[] result = new byte[length];
    for (int index = 0; index < length; index++) {
      result[index] = (byte) index;
    }
    return result;
  }

  public static class ReaderApplet extends Applet implements ExtendedLength {

    private final CBORApduReader reader = new CBORApduReader((short) 1200, CBORReader.PROFILE_CTAP);

    public static void install(byte[] parameters, short offset, byte length) {
      ReaderApplet applet = new ReaderApplet();
      installedReader = applet.reader;
      applet.register();
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        reader.clear();
        return;
      }
      if (apdu.getBuffer()[ISO7816.OFFSET_INS] == 1) {
        reader.clear();
      }
      short received = apdu.setIncomingAndReceive();
      if (!reader.receive(apdu, received, apdu.getOffsetCdata(), false)) {
        reader.clear();
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
    }

    @Override
    public void deselect() {
      super.deselect();
      reader.clear();
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
