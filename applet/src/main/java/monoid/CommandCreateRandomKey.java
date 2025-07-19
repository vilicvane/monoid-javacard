package monoid;

public class CommandCreateRandomKey extends Command {
  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    Keystore keystore = MonoidApplet.keystore;

    reader.map();
    byte type = Safe.type(reader.requireKey(Text.type).text());

    byte[] index;

    switch (type) {
      case Safe.TYPE_SEED:
        index = keystore.createRandomSeed();
        break;
      case Safe.TYPE_MASTER:
        index = keystore.createRandomMaster();
        break;
      case Safe.TYPE_KEY:
        reader.requireKey(Text.length);
        index = keystore.createRandomKey((byte) reader.integer());
        break;
      default:
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
    }

    writer.map((short) 1);
    {
      writer.text(Text.index);
      writer.bytes(index);
    }
  }
}
