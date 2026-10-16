package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public final class CBORMap {

  private final CBORReader reader;
  private final Object[] keys;
  private final short[] offsets;

  CBORMap(CBORReader reader, Object[] keys) {
    this.reader = reader;
    this.keys = keys;

    short length = reader.map();

    offsets = JCSystem.makeTransientShortArray((short) keys.length, JCSystem.CLEAR_ON_DESELECT);

    for (short index = 0; index < offsets.length; index++) {
      offsets[index] = -1;
    }

    for (short index = 0; length < 0 || index < length; index++) {
      if (reader.br()) {
        if (length < 0) {
          break;
        }

        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      short key = reader.readKey(keys);

      if (key >= 0 && offsets[key] < 0) {
        offsets[key] = reader.getOffset();
      }

      reader.skip();
    }
  }

  public boolean key(byte[] key) {
    for (short index = 0; index < keys.length; index++) {
      if (keys[index] == key || Utils.isEqual((byte[]) keys[index], key)) {
        if (offsets[index] < 0) {
          return false;
        }

        reader.setOffset(offsets[index]);
        return true;
      }
    }

    return false;
  }

  public CBORReader requireKey(byte[] key) {
    if (!key(key)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    return reader;
  }
}
