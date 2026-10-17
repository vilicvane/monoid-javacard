package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import monoidsafe.SafeShareable;

public class CommandImport extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    reader.requireKey(Text.index);
    byte[] index = readGlobalBytes(SafeShareable.INDEX_LENGTH);
    reader.requireKey(Text.senderPublicKey);
    byte[] senderPublicKey = readGlobalBytes((short) 65);
    byte[] key = reader.key(Text.key) ? readGlobalBytes((short) -1) : null;
    byte[] alias = reader.key(Text.alias) ? Utils.duplicateAsGlobal(reader.text()) : null;

    reader.requireKey(Text.data);
    byte[] data = readGlobalBytes((short) -1);

    MonoidApplet.safe.importItem(index, key, alias, senderPublicKey, data);

    sendEmptyMap();
  }

  private byte[] readGlobalBytes(short expectedLength) {
    short offset = reader.getOffset();
    short length = reader.bytesLength();

    if (expectedLength >= 0 && length != expectedLength) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    byte[] data = Utils.makeGlobalByteArray(length);
    ((CBORReader) reader).setOffset(offset);
    reader.bytes(data);
    return data;
  }
}
