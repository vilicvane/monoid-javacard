package monoidlib;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/** Indexes selected integer or text fields once without decoding their values. */
public final class CBORMap {

  private CBORReader reader;
  private final short[] integerKeys;
  private final Object[] textKeys;
  private final boolean sequentialKeys;
  // Zero means absent: a value always follows a map header and a key.
  private final short[] offsets;

  public CBORMap(CBORReader reader, short[] keys) {
    this(keys);
    read(reader);
  }

  public CBORMap(short[] keys) {
    integerKeys = keys;
    textKeys = null;
    boolean sequential = true;
    for (short index = 1; index < keys.length; index++) {
      if (keys[index] != (short) (keys[0] + index)) {
        sequential = false;
        break;
      }
    }
    sequentialKeys = sequential;
    offsets = JCSystem.makeTransientShortArray((short) keys.length, JCSystem.CLEAR_ON_DESELECT);
  }

  public CBORMap(CBORReader reader, Object[] keys) {
    this(keys);
    read(reader);
  }

  public CBORMap(Object[] keys) {
    integerKeys = null;
    textKeys = keys;
    sequentialKeys = false;
    offsets = JCSystem.makeTransientShortArray((short) keys.length, JCSystem.CLEAR_ON_DESELECT);
  }

  public void read(CBORReader reader) {
    if (this.reader != reader) {
      this.reader = reader;
    }
    for (short index = 0; index < offsets.length; index++) {
      offsets[index] = 0;
    }
    short count = reader.map();
    for (short index = 0; count < 0 || index < count; index++) {
      if (!reader.isStrict() && reader.br()) {
        if (count < 0) {
          break;
        }
        reader.invalid();
      }
      short field = integerKeys != null
        ? reader.readKey(integerKeys, sequentialKeys)
        : reader.readKey(textKeys);
      if (field >= 0) {
        if (offsets[field] == 0) {
          offsets[field] = reader.getOffset();
        } else if (reader.isStrict()) {
          reader.invalid();
        }
      }
      reader.skip();
    }
  }

  public boolean key(short key) {
    short index = indexOf(integerKeys, sequentialKeys, key);
    return index >= 0 && position(index);
  }

  static short indexOf(short[] keys, boolean sequential, short key) {
    if (sequential) {
      if (keys.length == 0) {
        return -1;
      }
      short index = (short) (key - keys[0]);
      return index >= 0 && index < keys.length ? index : (short) -1;
    }
    for (short index = 0; index < keys.length; index++) {
      if (keys[index] == key) {
        return index;
      }
    }
    return -1;
  }

  public boolean key(byte[] key) {
    for (short index = 0; index < textKeys.length; index++) {
      byte[] selected = (byte[]) textKeys[index];
      if (
        selected == key ||
        (!reader.isStrict() &&
          selected.length == key.length &&
          Util.arrayCompare(selected, (short) 0, key, (short) 0, (short) key.length) == 0)
      ) {
        return position(index);
      }
    }
    return false;
  }

  public CBORReader requireKey(short key) {
    if (!key(key)) {
      reader.missing();
    }
    return reader;
  }

  public CBORReader requireKey(byte[] key) {
    if (!key(key)) {
      reader.missing();
    }
    return reader;
  }

  private boolean position(short index) {
    if (offsets[index] == 0) {
      return false;
    }
    reader.setOffset(offsets[index]);
    return true;
  }
}
