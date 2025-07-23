package monoid;

public class CommandCreateRandomKey extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    Safe safe = MonoidApplet.safe;

    reader.map();

    short type = Safe.type(reader.requireKey(Text.type).text());

    if (Safe.isKnownExplicitLengthType(type)) {
      type |= reader.requireKey(Text.length).integer();
    }

    byte[] index = safe.createKnownRandom(type).getIndex();

    writer.map((short) 1);
    {
      writer.text(Text.index);
      writer.bytes(index);
    }
  }
}
