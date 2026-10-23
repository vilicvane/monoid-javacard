package monoidsecuritykey;

import static monoidsecuritykey.Constants.FIDO_VERSION;
import static monoidsecuritykey.Constants.KEY_CLIENT_PIN;
import static monoidsecuritykey.Constants.KEY_RK;
import static monoidsecuritykey.Constants.KEY_UP;

import monoidlib.CBORReader;
import monoidlib.CBORWriter;

final class CommandGetInfo extends Command {

  private static final byte[] AAGUID = new byte[16];

  @Override
  void execute(CBORReader reader, CBORWriter writer) {
    assertEmpty(reader);
    writer.map((short) 5);
    writer.integer((short) 1);
    writer.array((short) 1);
    writer.text(FIDO_VERSION);
    writer.integer((short) 3);
    writer.bytes(AAGUID);
    writer.integer((short) 4);
    writer.map((short) 3);
    writer.text(KEY_RK);
    writer.bool(true);
    writer.text(KEY_UP);
    writer.bool(true);
    writer.text(KEY_CLIENT_PIN);
    writer.bool(authenticator.pin.isSet());
    writer.integer((short) 5);
    writer.integer(CTAP.MAX_MESSAGE_LENGTH);
    writer.integer((short) 6);
    writer.array((short) 1);
    writer.integer((short) 1);
  }
}
