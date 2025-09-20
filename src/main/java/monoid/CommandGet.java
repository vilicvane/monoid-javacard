package monoid;

import monoidsafe.SafeItemShareable;
import monoidsafe.SafeShareable;

public class CommandGet extends Command {

  @Override
  protected void run() {
    requireAuth(AUTH_SAFE);

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(SafeShareable.INDEX_LENGTH);

    SafeItemShareable item = MonoidApplet.safe.require(index);

    byte[] alias = item.getAlias();
    byte[] data = item.getData();

    short entries = 1;

    if (alias != null) {
      entries++;
    }

    writer.map(entries);
    {
      if (alias != null) {
        writer.text(Text.alias);
        writer.text(alias);
      }

      writer.text(Text.data);
      writer.bytes(data);
    }
  }
}
