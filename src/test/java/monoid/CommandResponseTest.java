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
import monoidlib.CBORBufferReader;
import monoidlib.CBORResponse;
import monoidlib.CBORWriter;
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

  @Test
  public void executesOnlyTheCompleteRequestAndKeepsItsChainAfterGetResponse() {
    for (int[] frame : new int[][] { { 0x90, 0x19 }, { 0xB0, 0 } }) {
      ResponseAPDU response = simulator.transmitCommand(
        new CommandAPDU(frame[0], 0x30, 0, 0, new byte[] { (byte) frame[1] })
      );
      Assertions.assertEquals(0x9000, response.getSW());
      Assertions.assertEquals(0, response.getData().length);
      Assertions.assertEquals(0, responseCommand.executions);
    }

    Assertions.assertEquals(0x6883, next().getSW());
    Assertions.assertEquals(2, Command.reader.getReceivedLength());
    Assertions.assertEquals(0, responseCommand.executions);

    ResponseAPDU first = simulator.transmitCommand(
      new CommandAPDU(0xA0, 0x30, 0, 0, new byte[] { 0 })
    );
    Assertions.assertEquals(0x6100, first.getSW());
    Assertions.assertArrayEquals(new byte[] { (byte) 0x88, 0, 1, 2, 3 }, first.getData());
    Assertions.assertEquals(1, responseCommand.executions);
    Assertions.assertArrayEquals(new byte[] { 4, 5, 6, 7 }, next().getData());
    assertReleased();
  }

  @Test
  public void rejectsUnknownFirstInstructionAndDiscardsThePreviousRequest() {
    Assertions.assertEquals(
      0x9000,
      simulator.transmitCommand(new CommandAPDU(0x90, 0x30, 0, 0, new byte[] { 0x19 })).getSW()
    );
    Assertions.assertEquals(
      0x6D00,
      simulator.transmitCommand(new CommandAPDU(0x90, 0x7F, 0, 0, new byte[] { 0 })).getSW()
    );
    Assertions.assertEquals(0, Command.reader.getReceivedLength());
    Assertions.assertEquals(0, responseCommand.executions);
    Assertions.assertEquals(
      0x6883,
      simulator.transmitCommand(new CommandAPDU(0xA0, 0x30, 0, 0, new byte[] { 0, 0 })).getSW()
    );

    Assertions.assertEquals(0x6100, start(0).getSW());
    Assertions.assertEquals(1, responseCommand.executions);
    Assertions.assertArrayEquals(new byte[] { 4, 5, 6, 7 }, next().getData());
    assertReleased();
  }

  @Test
  public void rejectsChangedParametersInMoreAndLastFrames() {
    for (int cla : new int[] { 0xB0, 0xA0 }) {
      for (int[] parameters : new int[][] { { 1, 0 }, { 0, 1 } }) {
        Assertions.assertEquals(
          0x9000,
          simulator.transmitCommand(new CommandAPDU(0x90, 0x30, 0, 0, new byte[] { 0x19 })).getSW()
        );
        ResponseAPDU changed = simulator.transmitCommand(
          new CommandAPDU(cla, 0x30, parameters[0], parameters[1], new byte[] { 0 })
        );
        Assertions.assertEquals(0x6883, changed.getSW());
        Assertions.assertEquals(0, Command.reader.getReceivedLength());
        Assertions.assertEquals(0, responseCommand.executions);
        Assertions.assertEquals(
          0x6883,
          simulator.transmitCommand(new CommandAPDU(0xA0, 0x30, 0, 0, new byte[] { 0, 0 })).getSW()
        );
      }
    }
    Assertions.assertEquals(0x6100, start(0).getSW());
    Assertions.assertArrayEquals(new byte[] { 4, 5, 6, 7 }, next().getData());
    assertReleased();
  }

  @Test
  public void preservesThePendingResponseAfterInvalidGetResponseHeaders() {
    Assertions.assertEquals(0x6100, start(0).getSW());
    for (int[] header : new int[][] {
      { 0x80, 0, 0, 0x6E00 },
      { 0, 1, 0, 0x6A86 },
      { 0, 0, 1, 0x6A86 },
    }) {
      ResponseAPDU invalid = simulator.transmitCommand(
        new CommandAPDU(header[0], 0xC0, header[1], header[2], 256)
      );
      Assertions.assertEquals(header[3], invalid.getSW());
      Assertions.assertEquals(0, invalid.getData().length);
      Assertions.assertTrue(Command.writer.hasPending());
      Assertions.assertTrue(responseCommand.active);
    }
    ResponseAPDU last = next();
    Assertions.assertEquals(0x9000, last.getSW());
    Assertions.assertArrayEquals(new byte[] { 4, 5, 6, 7 }, last.getData());
    Assertions.assertEquals(1, responseCommand.executions);
    assertReleased();
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
    private int executions;

    @Override
    protected void run() {
      executions++;
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

    private final ApduTransport transport = new ApduTransport(Command.reader, Command.writer);

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

  public static class EmptyApplet extends Applet {

    public static void install(byte[] data, short offset, byte length) {
      new EmptyApplet().register();
    }

    @Override
    public void process(APDU apdu) {}
  }
}
