package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

import monoidsafe.MonoidSafe;

public class CommandSet extends Command {
  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(MonoidSafe.INDEX_LENGTH);
    byte[] data = reader.requireKey(Text.data).bytes();

    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE,
        (short) (index.length + data.length));

    Util.arrayCopyNonAtomic(index, (short) 0, buffer, (short) 0, (short) index.length);
    Util.arrayCopyNonAtomic(data, (short) 0, buffer, (short) index.length, (short) data.length);

    MonoidApplet.safe.set(buffer, (short) 0, (short) buffer.length);

    sendEmptyMap();
  }
}
