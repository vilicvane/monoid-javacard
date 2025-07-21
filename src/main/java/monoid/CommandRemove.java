package monoid;

import monoidsafe.MonoidSafe;

public class CommandRemove extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(MonoidSafe.INDEX_LENGTH);

    MonoidApplet.safe.remove(index);

    sendEmptyMap();
  }
}
