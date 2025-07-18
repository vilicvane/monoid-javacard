package monoid;

public class CommandList extends Command {
  @Override
  protected void run() throws MonoidException {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte type = reader.key(Text.type) ? Safe.type(reader) : 0;

    byte[] data = MonoidApplet.safe.list(type, Safe.INDEX_LENGTH);

    writer.map((short) 1);
    {
      writer.text(Text.indexes);
      writer.array((short) (data.length / Safe.INDEX_LENGTH));
      for (short offset = 0; offset < data.length; offset += Safe.INDEX_LENGTH) {
        writer.bytes(data, offset, Safe.INDEX_LENGTH);
      }
    }

    writer.send();
  }
}
