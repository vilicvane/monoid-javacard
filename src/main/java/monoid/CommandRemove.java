package monoid;

public class CommandRemove extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.safe.checkAccess();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(Safe.INDEX_LENGTH);

    MonoidApplet.safe.require(index).remove();

    sendEmptyMap();
  }
}
