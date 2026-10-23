package monoidsecuritykey;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import monoidlib.CBORReader;
import monoidlib.CBORWriter;

abstract class Command {

  static Authenticator authenticator;
  private static Command makeCredential;
  private static CommandGetAssertion getAssertion;
  private static Command getInfo;
  private static Command clientPIN;
  private static Command reset;

  static void init() {
    authenticator = new Authenticator();
    makeCredential = new CommandMakeCredential();
    getAssertion = new CommandGetAssertion();
    getInfo = new CommandGetInfo();
    clientPIN = new CommandClientPIN();
    reset = new CommandReset();
  }

  static void dispose() {
    authenticator = null;
    makeCredential = null;
    getAssertion = null;
    getInfo = null;
    clientPIN = null;
    reset = null;
  }

  static void clear() {
    getAssertion.clearAssertion();
    authenticator.pin.deselect();
    JCSystem.requestObjectDeletion();
  }

  static void process(byte instruction, CBORReader reader, CBORWriter writer) {
    if (instruction != 0x08) {
      getAssertion.clearAssertion();
    }
    Command command;
    switch (instruction) {
      case 0x01:
        command = makeCredential;
        break;
      case 0x02:
        command = getAssertion;
        break;
      case 0x04:
        command = getInfo;
        break;
      case 0x06:
        command = clientPIN;
        break;
      case 0x07:
        command = reset;
        break;
      case 0x08:
        assertEmpty(reader);
        getAssertion.next(writer);
        return;
      default:
        ISOException.throwIt(CTAP.INVALID_COMMAND);
        return;
    }
    command.execute(reader, writer);
  }

  static void assertEmpty(CBORReader reader) {
    if (!reader.atEnd()) {
      ISOException.throwIt(CTAP.INVALID_LENGTH);
    }
  }

  abstract void execute(CBORReader reader, CBORWriter writer);
}
