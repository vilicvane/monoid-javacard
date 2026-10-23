package monoid;

import static monoid.Constants.SAFE_FALSE;
import static monoid.Constants.SAFE_TRUE;

import monoidlib.LibSecurity;

public class CommandGet extends Command {

  private final SafeDataResponse response = new SafeDataResponse();

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.safe.checkAccess();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(Safe.INDEX_LENGTH);

    final SafeItem item = MonoidApplet.safe.require(index);

    LibSecurity.Condition secret = new LibSecurity.Condition() {
      @Override
      public boolean check() {
        return item.isSecret();
      }
    };

    if (LibSecurity.check(secret, SAFE_TRUE) != SAFE_FALSE) {
      MonoidException.throwIt(MonoidException.CODE_ACCESS_DENIED);
    }

    short length = response.start(writer, item.getData(), (short) (2 + Text.data.length));

    writer.map((short) 1);
    {
      writer.text(Text.data);
      writer.bytesLength(length);
      response.writeData(writer);
    }
  }
}
