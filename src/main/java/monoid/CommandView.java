package monoid;

import monoidsafe.SafeItemShareable;
import monoidsafe.SafeShareable;

public class CommandView extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(SafeShareable.INDEX_LENGTH);

    SafeItemShareable item = MonoidApplet.safe.require(index);

    byte[] alias = item.getAlias();

    short entries = 0;

    if (alias != null) {
      entries++;
    }

    writer.map(entries);
    {
      if (alias != null) {
        writer.text(Text.alias);
        writer.text(alias);
      }
    }
  }
}
