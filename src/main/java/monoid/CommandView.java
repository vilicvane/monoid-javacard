package monoid;

public class CommandView extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(Safe.INDEX_LENGTH);

    SafeItem item = MonoidApplet.safe.require(index);

    byte[] key = item.getKey();
    byte[] alias = item.getAlias();

    short entries = 1;

    if (key != null) {
      entries++;
    }

    if (alias != null) {
      entries++;
    }

    writer.map(entries);
    {
      if (key != null) {
        writer.text(Text.key);
        writer.bytes(key);
      }

      if (alias != null) {
        writer.text(Text.alias);
        writer.text(alias);
      }

      writer.text(Text.secret);
      writer.bool(item.isSecret());
    }
  }
}
