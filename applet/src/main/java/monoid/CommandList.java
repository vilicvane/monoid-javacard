package monoid;

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

    byte[] data = MonoidApplet.safe.list(type, Safe.INDEX_LENGTH);

    writer.map((short) 1);
    {
      writer.text(Text.items);
      writer.array((short) (data.length / Safe.INDEX_LENGTH));
      for (short offset = 0; offset < data.length; offset += Safe.INDEX_LENGTH) {
        writer.map((short) 2);
        {
          writer.text(Text.type);
          writer.text(Safe.type(data[offset]));

          writer.text(Text.index);
          writer.bytes(data, offset, Safe.INDEX_LENGTH);
        }
      }
    }
  }
}
