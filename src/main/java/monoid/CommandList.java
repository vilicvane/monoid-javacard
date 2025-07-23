package monoid;

import javacard.framework.Util;
import monoidsafe.SafeItemShareable;
import monoidsafe.SafeShareable;

public class CommandList extends Command {

  @Override
  protected void run() throws MonoidException {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    short type = reader.key(Text.type)
      ? reader.is(CBOR.TYPE_TEXT) ? Safe.type(reader) : reader.integer()
      : 0;

    Object[] items = MonoidApplet.safe.list(type);

    writer.map((short) 1);
    {
      writer.text(Text.items);
      writer.array((short) items.length);
      for (short itemIndex = 0; itemIndex < items.length; itemIndex++) {
        SafeItemShareable item = (SafeItemShareable) items[itemIndex];

        byte[] index = item.getIndex();
        byte[] typeName = Safe.type(Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET));
        byte[] alias = item.getAlias();

        short entries = 1;

        if (typeName != null) {
          entries++;
        }

        if (alias != null) {
          entries++;
        }

        writer.map(entries);
        {
          if (typeName != null) {
            writer.text(Text.type);
            writer.text(typeName);
          }

          if (alias != null) {
            writer.text(Text.alias);
            writer.text(alias);
          }

          writer.text(Text.index);
          writer.bytes(index);
        }
      }
    }
  }
}
