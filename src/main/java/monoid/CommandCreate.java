package monoid;

import monoidsafe.SafeItemShareable;
import monoidsafe.SafeShareable;

public class CommandCreate extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    SafeData data = SafeData.fromReader(reader.requireKey(Text.data));
    byte[] key = reader.key(Text.key) ? reader.bytes() : null;
    byte[] alias = reader.key(Text.alias) ? reader.text() : null;
    boolean secret = reader.key(Text.secret) && reader.bool();

    SafeItemShareable item;

    if (reader.key(Text.type)) {
      short type = reader.is(CBOR.TYPE_TEXT) ? Safe.type(reader) : reader.integer();

      item = MonoidApplet.safe.create(type, key, alias, data, secret);
    } else {
      byte[] index = reader.requireKey(Text.index).bytes(SafeShareable.INDEX_LENGTH);

      item = MonoidApplet.safe.create(index, key, alias, data, secret);
    }

    writer.map((short) 1);
    {
      writer.text(Text.index);
      writer.bytes(item.getIndex());
    }
  }
}
