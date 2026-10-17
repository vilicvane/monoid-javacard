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
    boolean hasSecret = reader.key(Text.secret);
    boolean secret = hasSecret && reader.bool();

    SafeItemShareable item = MonoidApplet.safe.require(index);

    if (data != null) {
      data = Utils.duplicateAsGlobal(data);

      if (hasSecret) {
        item.setData(data, secret);
      } else {
        item.setData(data);
      }
    } else if (hasSecret) {
      item.setSecret(secret);
    }

    if (alias != null) {
      item.setAlias(Utils.duplicateAsGlobal(alias));
    }

    sendEmptyMap();
  }
}
