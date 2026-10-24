package monoid;

import monoidlib.CBOR;

public class CommandCreate extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.safe.checkAccess();

    reader.map();

    SafeData data = SafeData.fromReader(reader.requireKey(Text.data));
    byte[] metadata = reader.key(Text.metadata) ? reader.bytes() : null;
    byte[] alias = reader.key(Text.alias) ? reader.text() : null;
    boolean secret = reader.key(Text.secret) && reader.bool();

    SafeItem item;

    if (reader.key(Text.type)) {
      short type = reader.is(CBOR.TYPE_TEXT) ? Safe.type(reader) : reader.integer();

      item = MonoidApplet.safe.create(type, metadata, alias, data, secret);
    } else {
      byte[] index = reader.requireKey(Text.index).bytes(Safe.INDEX_LENGTH);

      item = MonoidApplet.safe.create(index, metadata, alias, data, secret);
    }

    writer.map((short) 1);
    {
      writer.text(Text.index);
      writer.bytes(item.getIndex());
    }
  }
}
