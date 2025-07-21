package monoid;

import monoidsafe.MonoidSafe;

public class CommandGet extends Command {

  @Override
  protected void run() {
    requireAuth(AUTH_SAFE);

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(MonoidSafe.INDEX_LENGTH);

    byte[] data = MonoidApplet.safe.require(index);

    writer.map((short) 1);
    {
      writer.text(Text.data);
      writer.bytes(data);
    }
  }
}
