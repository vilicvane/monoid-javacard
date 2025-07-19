package monoid;

import monoidsafe.MonoidSafe;

public class CommandList extends Command {
  @Override
  protected void run() throws MonoidException {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte type = reader.key(Text.type)
        ? reader.is(CBOR.TYPE_TEXT)
            ? Safe.type(reader)
            : (byte) reader.integer()
        : 0;

    byte[] data = MonoidApplet.safe.list(type);

    writer.map((short) 1);
    {
      writer.text(Text.items);
      writer.array((short) (data.length / MonoidSafe.INDEX_LENGTH));
      for (short offset = 0; offset < data.length; offset += MonoidSafe.INDEX_LENGTH) {
        byte[] typeName = Safe.type(data[offset]);

        writer.map((short) (typeName == null ? 1 : 2));
        {
          if (typeName != null) {
            writer.text(Text.type);
            writer.text(typeName);
          }

          writer.text(Text.index);
          writer.bytes(data, offset, MonoidSafe.INDEX_LENGTH);
        }
      }
    }
  }
}
