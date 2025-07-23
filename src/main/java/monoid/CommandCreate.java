package monoid;

import monoidsafe.SafeItemShareable;
import monoidsafe.SafeShareable;

public class CommandCreate extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte[] data = reader.requireKey(Text.data).bytes();
    byte[] alias = reader.key(Text.alias) ? reader.text() : null;

    SafeItemShareable item;

    if (reader.key(Text.type)) {
      short type = reader.key(Text.type)
        ? reader.is(CBOR.TYPE_TEXT) ? Safe.type(reader) : reader.integer()
        : 0;

      item = MonoidApplet.safe.create(type, alias, data);
    } else {
      byte[] index = reader.requireKey(Text.index).bytes(SafeShareable.INDEX_LENGTH);

      item = MonoidApplet.safe.create(index, alias, data);
    }

    writer.map((short) 1);
    {
      writer.text(Text.index);
      writer.bytes(item.getIndex());
    }
  }
}
