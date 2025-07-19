package monoid;

import monoidsafe.MonoidSafe;

public class CommandGet extends Command {
  @Override
  protected void run() {
    requireAuth(AUTH_SAFE);

    reader.map();

    byte[] index = Utils.duplicateAsGlobal(reader.requireKey(Text.index).bytes(MonoidSafe.INDEX_LENGTH));

    byte[] data = MonoidApplet.safe.get(index, (short) 0);

    if (data == null) {
      MonoidException.throwIt(MonoidException.CODE_NOT_FOUND);
      return;
    }

    writer.map((short) 1);
    {
      writer.text(Text.data);
      writer.bytes(data);
    }
  }
}
