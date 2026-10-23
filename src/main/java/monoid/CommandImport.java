package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import monoidlib.CBORReader;

public class CommandImport extends Command {

  @Override
  protected void run() {
    requireAuth(AUTH_SECRET);

    MonoidApplet.safe.checkAccess();

    reader.map();

    reader.requireKey(Text.index);
    byte[] index = readBytes(Safe.INDEX_LENGTH);
    byte[] senderPublicKey = reader.key(Text.senderPublicKey) ? readBytes((short) 65) : null;
    byte[] key = reader.key(Text.key) ? readBytes((short) -1) : null;
    byte[] alias = reader.key(Text.alias) ? reader.text() : null;

    reader.requireKey(Text.data);
    SafeData data = SafeData.fromReader(reader);

    MonoidApplet.safe.importItem(index, key, alias, senderPublicKey, data);

    sendEmptyMap();
  }

  private byte[] readBytes(short expectedLength) {
    short offset = reader.getOffset();
    short length = reader.bytesLength();

    if (expectedLength >= 0 && length != expectedLength) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    byte[] data = new byte[length];
    // Work around CAP converter lookup failures by referencing setOffset's declaring class.
    ((CBORReader) reader).setOffset(offset);
    reader.bytes(data);
    return data;
  }
}
