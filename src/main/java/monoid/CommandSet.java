package monoid;

import monoidsafe.SafeItemShareable;
import monoidsafe.SafeShareable;

public class CommandSet extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(SafeShareable.INDEX_LENGTH);
    byte[] alias = reader.key(Text.alias) ? reader.text() : null;
    byte[] data = reader.key(Text.data) ? reader.bytes() : null;

    SafeItemShareable item = MonoidApplet.safe.require(index);

    if (alias != null) {
      item.setAlias(Utils.duplicateAsGlobal(alias));
    }

    if (data != null) {
      item.setData(Utils.duplicateAsGlobal(data));
    }

    sendEmptyMap();
  }
}
