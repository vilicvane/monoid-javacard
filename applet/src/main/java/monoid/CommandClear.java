package monoid;

import monoidsafe.MonoidSafe;

public class CommandClear extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte[] index = Utils.duplicateAsGlobal(
      reader.requireKey(Text.index).bytes(MonoidSafe.INDEX_LENGTH)
    );

    MonoidApplet.safe.clear(index, (short) 0);

    sendEmptyMap();
  }
}
