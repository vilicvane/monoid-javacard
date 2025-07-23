package monoid;

import monoidsafe.SafeShareable;

public class CommandRemove extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(SafeShareable.INDEX_LENGTH);

    MonoidApplet.safe.require(index).remove();

    sendEmptyMap();
  }
}
