package monoid;

public class CommandExport extends Command {

  private final SafeDataResponse response = new SafeDataResponse();

  @Override
  protected void run() {
    requireAuth(AUTH_SAFE);

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(Safe.INDEX_LENGTH);
    byte[] recipientPublicKey = reader.requireKey(Text.recipientPublicKey).bytes((short) 65);

    SafeItem item = MonoidApplet.safe.require(index);

    byte[] key = item.getKey();
    byte[] alias = item.getAlias();
    SafeDataSource data = item.exportData(recipientPublicKey);

    short entries = 1;

    short prefixLength = (short) (2 + Text.data.length);

    if (key != null) {
      entries++;
      prefixLength += (short) (1 +
        Text.key.length +
        CBORWriter.metadataLength((short) key.length) +
        key.length);
    }

    if (alias != null) {
      entries++;
      prefixLength += (short) (1 +
        Text.alias.length +
        CBORWriter.metadataLength((short) alias.length) +
        alias.length);
    }

    short length = response.start(writer, data, prefixLength);

    writer.map(entries);
    {
      if (key != null) {
        writer.text(Text.key);
        writer.bytes(key);
      }

      if (alias != null) {
        writer.text(Text.alias);
        writer.text(alias);
      }

      writer.text(Text.data);
      writer.bytesLength(length);
      response.writeData(writer);
    }
  }
}
