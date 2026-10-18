package monoid;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CommandResponseTest {

  private static final AID RESPONSE_AID = AIDUtil.create("f06d6f6e6f69647f01");
  private static final AID OTHER_AID = AIDUtil.create("f06d6f6e6f69647f02");

  private static ResponseCommand responseCommand;

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    simulator = new CardSimulator();
    simulator.installApplet(RESPONSE_AID, ResponseApplet.class);
    simulator.installApplet(OTHER_AID, EmptyApplet.class);
    Assertions.assertTrue(simulator.selectApplet(RESPONSE_AID));
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(RESPONSE_AID);
    simulator.deleteApplet(OTHER_AID);
    Command.dispose();
    MonoidException.dispose();
    responseCommand = null;
  }

  @Test
  public void mapsInitialGenerationFailureToTheNormalErrorResponse() {
    ResponseAPDU response = start(1);
    Assertions.assertEquals(0x9000, response.getSW());
    CBORBufferReader reader = new CBORBufferReader(response.getData());
    reader.map();
    reader.requireKey(Text.error).map();
    Assertions.assertArrayEquals(
      MonoidException.CODE_NOT_FOUND,
      reader.requireKey(Text.code).text()
    );
    assertReleased();
  }

  @Test
  public void terminatesContinuationFailureWithoutAppendingAnErrorObject() {
    for (int mode : new int[] { 2, 3, 4 }) {
      ResponseAPDU first = start(mode);
      Assertions.assertEquals(0x6100, first.getSW());
      Assertions.assertArrayEquals(new byte[] { (byte) 0x88, 0, 1, 2, 3 }, first.getData());

      ResponseAPDU last = next();
      Assertions.assertEquals(mode == 4 ? 0x6982 : 0x6F00, last.getSW());
      Assertions.assertEquals(0, last.getData().length);
      assertReleased();
      Assertions.assertEquals(0x6985, next().getSW());
    }
  }

  @Test
  public void releasesTheSourceAfterCompletionOrANewCommand() {
    Assertions.assertEquals(0x6100, start(0).getSW());
    Assertions.assertArrayEquals(new byte[] { 4, 5, 6, 7 }, next().getData());
    assertReleased();

    Assertions.assertEquals(0x6100, start(0).getSW());
    ResponseAPDU replacement = simulator.transmitCommand(
      new CommandAPDU(0, 0x20, 0, 0, new byte[] { 0 })
    );
    Assertions.assertEquals(0x9000, replacement.getSW());
    Assertions.assertArrayEquals(new byte[] { (byte) 0xA0 }, replacement.getData());
    assertReleased();
    Assertions.assertEquals(0x6985, next().getSW());
  }

  @Test
  public void releasesTheSourceOnDeselectAndReset() {
    Assertions.assertEquals(0x6100, start(0).getSW());
    Assertions.assertTrue(simulator.selectApplet(OTHER_AID));
    assertReleased();
    Assertions.assertTrue(simulator.selectApplet(RESPONSE_AID));
    Assertions.assertEquals(0x6985, next().getSW());

    Assertions.assertEquals(0x6100, start(0).getSW());
    simulator.reset();
    Assertions.assertTrue(simulator.selectApplet(RESPONSE_AID));
    assertReleased();
    Assertions.assertEquals(0x6985, next().getSW());
  }

  private ResponseAPDU start(int mode) {
    return simulator.transmitCommand(new CommandAPDU(0, 0x30, 0, 0, new byte[] { (byte) mode }));
  }

  private ResponseAPDU next() {
    return simulator.transmitCommand(new CommandAPDU(0, 0xC0, 0, 0, 256));
  }

  private void assertReleased() {
    Assertions.assertFalse(Command.writer.hasPending());
    Assertions.assertFalse(responseCommand.active);
  }

  private static class ResponseCommand extends Command implements CBORResponse {

    private short mode;
    private short position;
    private boolean active;

    @Override
    protected void run() {
      mode = reader.integer();
      writer.start(this, (short) 1);
      active = true;
      writer.array((short) 8);
    }

    @Override
    public boolean writeNext(CBORWriter writer) {
      if ((mode == 1 && position == 0) || (mode == 2 && position == 4)) {
        MonoidException.throwIt(MonoidException.CODE_NOT_FOUND);
      }

      if (mode == 3 && position == 4) {
        throw new SecurityException();
      }

      if (mode == 4 && position == 4) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      writer.integer(position++);
      return position < 8;
    }

    @Override
    public void reset() {
      position = 0;
      active = false;
    }
  }

  public static class ResponseApplet extends Applet {

    public static void install(byte[] data, short offset, byte length) {
      MonoidException.init();
      Command.init();
      responseCommand = new ResponseCommand();
      Command.list = responseCommand;
      Command.hello = new Command() {
        @Override
        protected void run() {
          writer.map((short) 0);
        }
      };
      new ResponseApplet().register();
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        Command.clearTransport();
        return;
      }

      Command.process(apdu);
    }

    @Override
    public void deselect() {
      super.deselect();
      Command.clearTransport();
    }
  }

  public static class EmptyApplet extends Applet {

    public static void install(byte[] data, short offset, byte length) {
      new EmptyApplet().register();
    }

    @Override
    public void process(APDU apdu) {}
  }
}
