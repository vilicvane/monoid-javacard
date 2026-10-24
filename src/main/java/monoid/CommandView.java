package monoid;

public class CommandView extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.safe.checkAccess();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(Safe.INDEX_LENGTH);

    SafeItem item = MonoidApplet.safe.require(index);

    byte[] metadata = item.getMetadata();
    byte[] alias = item.getAlias();

    short entries = 1;

    if (metadata != null) {
      entries++;
    }

    if (alias != null) {
      entries++;
    }

    writer.map(entries);
    {
      if (metadata != null) {
        writer.text(Text.metadata);
        writer.bytes(metadata);
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
