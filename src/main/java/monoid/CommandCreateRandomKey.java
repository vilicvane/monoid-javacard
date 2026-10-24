package monoid;

public class CommandCreateRandomKey extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.safe.checkAccess();

    Safe safe = MonoidApplet.safe;

    reader.map();

    short type = Safe.type(reader.requireKey(Text.type).text());

    if (Safe.isKnownExplicitLengthType(type)) {
      short length = reader.requireKey(Text.length).integer();

      if (Safe.isTypeHmac(type) && (length < 1 || length > Safe.TYPE_METADATA_MASK)) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      }

      type |= length;
    }

    byte[] index = safe.createKnownRandom(type).getIndex();

    writer.map((short) 1);
    {
      writer.text(Text.index);
      writer.bytes(index);
    }
  }
}
