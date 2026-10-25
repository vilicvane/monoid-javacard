package monoid;

public class CommandRemove extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.safe.checkAccess();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(Safe.INDEX_LENGTH);

    SafeItem item = MonoidApplet.safe.get(index);

    if (item != null) {
      item.remove();
    }

    writer.map((short) 1);
    {
      writer.text(Text.removed);
      writer.bool(item != null);
    }
  }
}
