package monoid;

public class CommandSet extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.safe.checkAccess();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(Safe.INDEX_LENGTH);
    byte[] alias = reader.key(Text.alias) ? reader.text() : null;
    SafeData data = reader.key(Text.data) ? SafeData.fromReader(reader) : null;
    boolean hasSecret = reader.key(Text.secret);
    boolean secret = hasSecret && reader.bool();

    SafeItem item = MonoidApplet.safe.require(index);

    if (data != null) {
      if (hasSecret) {
        item.setData(data, secret);
      } else {
        item.setData(data);
      }
    } else if (hasSecret) {
      item.setSecret(secret);
    }

    if (alias != null) {
      item.setAlias(alias);
    }

    writeEmptyMap();
  }
}
