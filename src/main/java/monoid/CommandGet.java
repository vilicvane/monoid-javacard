package monoid;

import static monoidsafe.Constants.SAFE_FALSE;
import static monoidsafe.Constants.SAFE_TRUE;

import monoidsafe.SafeItemShareable;
import monoidsafe.SafeShareable;

public class CommandGet extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(SafeShareable.INDEX_LENGTH);

    final SafeItemShareable item = MonoidApplet.safe.require(index);

    LibSecurity.Condition secret = new LibSecurity.Condition() {
      @Override
      public boolean check() {
        return item.isSecret();
      }
    };

    if (LibSecurity.check(secret, SAFE_TRUE) != SAFE_FALSE) {
      MonoidException.throwIt(MonoidException.CODE_ACCESS_DENIED);
    }

    writer.map((short) 1);
    {
      writer.text(Text.data);
      writer.bytes(item.getData());
    }
  }
}
