package monoid;

public class CommandClear extends Command {
  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte[] index = Utils.duplicateAsGlobal(reader.requireKey(Text.index).bytes());

    MonoidApplet.safe.clear(index, (short) 0, (byte) index.length);

    sendEmptyMap();
  }
}
