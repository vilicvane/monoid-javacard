package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public abstract class CBORReader implements ByteSource {

  private static final short OFFSET = 0;
  private static final short ARRAY_OFFSET = 1;
  private static final short MAP_LENGTH = 2;
  private static final short MAP_OFFSET = 3;
  private static final short SNAPSHOT_INDEX = 4;

  private static final short MAX_SNAPSHOTS = 8;

  private final short[] state = JCSystem.makeTransientShortArray(
    (short) 5,
    JCSystem.CLEAR_ON_DESELECT
  );

  private final short[] offsetSnapshots = JCSystem.makeTransientShortArray(
    MAX_SNAPSHOTS,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final short[] arrayOffsetSnapshots = JCSystem.makeTransientShortArray(
    MAX_SNAPSHOTS,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final short[] mapLengthSnapshots = JCSystem.makeTransientShortArray(
    MAX_SNAPSHOTS,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final short[] mapOffsetSnapshots = JCSystem.makeTransientShortArray(
    MAX_SNAPSHOTS,
    JCSystem.CLEAR_ON_DESELECT
  );

  protected abstract short getLength();

  public short getOffset() {
    return state[OFFSET];
  }

  void setOffset(short offset) {
    state[OFFSET] = offset;
  }

  private void requireRange(short offset, short length) {
    if (offset < 0 || length < 0 || offset > (short) (getLength() - length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  private void requireLength(short length) {
    requireRange(state[OFFSET], length);
  }

  private byte read(short offset) {
    requireRange(offset, (short) 1);
    return getChunk(offset)[getChunkOffset(offset)];
  }

  private void read(short offset, byte[] out, short outOffset, short length) {
    requireRange(offset, length);

    while (length > 0) {
      short chunkLength = getChunkLength(offset);

      if (chunkLength > length) {
        chunkLength = length;
      }

      Util.arrayCopyNonAtomic(
        getChunk(offset),
        getChunkOffset(offset),
        out,
        outOffset,
        chunkLength
      );

      offset += chunkLength;
      outOffset += chunkLength;
      length -= chunkLength;
    }
  }

  protected void reset(short offset) {
    state[OFFSET] = offset;

    state[ARRAY_OFFSET] = -1;
    state[MAP_OFFSET] = -1;

    resetSnapshot();
  }

  public void snapshot() {
    state[SNAPSHOT_INDEX]++;
    offsetSnapshots[state[SNAPSHOT_INDEX]] = state[OFFSET];
    arrayOffsetSnapshots[state[SNAPSHOT_INDEX]] = state[ARRAY_OFFSET];
    mapLengthSnapshots[state[SNAPSHOT_INDEX]] = state[MAP_LENGTH];
    mapOffsetSnapshots[state[SNAPSHOT_INDEX]] = state[OFFSET];
  }

  public void resetSnapshot() {
    state[SNAPSHOT_INDEX] = 0;
    offsetSnapshots[0] = state[OFFSET];
    arrayOffsetSnapshots[0] = state[ARRAY_OFFSET];
    mapLengthSnapshots[0] = state[MAP_LENGTH];
    mapOffsetSnapshots[0] = state[OFFSET];
  }

  public void popSnapshot(boolean restore) {
    state[SNAPSHOT_INDEX]--;

    if (restore) {
      restore();
    }
  }

  public void popSnapshot() {
    popSnapshot(true);
  }

  public void restore() {
    state[OFFSET] = offsetSnapshots[state[SNAPSHOT_INDEX]];
    state[ARRAY_OFFSET] = arrayOffsetSnapshots[state[SNAPSHOT_INDEX]];
    state[MAP_LENGTH] = mapLengthSnapshots[state[SNAPSHOT_INDEX]];
    state[MAP_OFFSET] = mapOffsetSnapshots[state[SNAPSHOT_INDEX]];
  }

  public boolean is(byte type) {
    return (read(state[OFFSET]) & CBOR.TYPE_MASK) == type;
  }

  public short integer() {
    byte type = (byte) (read(state[OFFSET]) & CBOR.TYPE_MASK);

    switch (type) {
      case CBOR.TYPE_UNSIGNED_INT:
        return metadataUnsignedInteger();
      case CBOR.TYPE_NEGATIVE_INT: {
        return (short) (-metadataUnsignedInteger() - 1);
      }
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return -1;
    }
  }

  public short bytes(byte[] out, short outOffset) {
    return bytesLike(CBOR.TYPE_BYTES, out, outOffset);
  }

  public short bytes(byte[] out) {
    return bytesLike(CBOR.TYPE_BYTES, out, (short) 0);
  }

  public byte[] bytes() {
    return bytesLike(CBOR.TYPE_BYTES);
  }

  /** Read the byte-string header, leaving getOffset() at its logical content offset. */
  public short bytesLength() {
    return bytesLikeLength(CBOR.TYPE_BYTES);
  }

  public byte[] bytes(short expectedLength) {
    byte[] bytes = bytesLike(CBOR.TYPE_BYTES);

    if (bytes.length != expectedLength) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    return bytes;
  }

  public short text(byte[] out, short outOffset) {
    return bytesLike(CBOR.TYPE_TEXT, out, outOffset);
  }

  public short text(byte[] out) {
    return bytesLike(CBOR.TYPE_TEXT, out, (short) 0);
  }

  public byte[] text() {
    return bytesLike(CBOR.TYPE_TEXT);
  }

  private short bytesLikeLength(byte type) {
    if ((read(state[OFFSET]) & CBOR.TYPE_MASK) != type) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short length = metadataUnsignedInteger();

    requireLength(length);

    return length;
  }

  private short bytesLike(byte type, byte[] out, short outOffset) {
    short length = bytesLikeLength(type);

    read(state[OFFSET], out, outOffset, length);

    state[OFFSET] += length;

    return length;
  }

  private byte[] bytesLike(byte type) {
    short length = bytesLikeLength(type);

    byte[] out = JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);

    read(state[OFFSET], out, (short) 0, length);

    return out;
  }

  public short array() {
    if ((read(state[OFFSET]) & CBOR.TYPE_MASK) != CBOR.TYPE_ARRAY) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short length = metadataItemsLength();

    state[ARRAY_OFFSET] = state[OFFSET];

    return length;
  }

  public boolean index(short index) {
    state[OFFSET] = state[ARRAY_OFFSET];

    for (short skipping = 0; skipping <= index; skipping++) {
      if (read(state[OFFSET]) == CBOR.BREAK) {
        break;
      }

      if (skipping == index) {
        return true;
      }

      skip();
    }

    state[OFFSET] = state[ARRAY_OFFSET];

    return false;
  }

  public short map() {
    if ((read(state[OFFSET]) & CBOR.TYPE_MASK) != CBOR.TYPE_MAP) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    state[MAP_LENGTH] = metadataItemsLength();

    state[MAP_OFFSET] = state[OFFSET];

    return state[MAP_LENGTH];
  }

  public CBORMap map(Object[] keys) {
    return new CBORMap(this, keys);
  }

  short readKey(Object[] keys) {
    short length = bytesLikeLength(CBOR.TYPE_TEXT);
    short offset = state[OFFSET];

    state[OFFSET] += length;

    for (short index = 0; index < keys.length; index++) {
      byte[] key = (byte[]) keys[index];

      if (key.length != length) {
        continue;
      }

      short matched = 0;

      while (matched < length && read((short) (offset + matched)) == key[matched]) {
        matched++;
      }

      if (matched == length) {
        return index;
      }
    }

    return -1;
  }

  public boolean key(byte[] in, short keyOffset, short keyLength) {
    state[OFFSET] = state[MAP_OFFSET];

    for (short index = 0; state[MAP_LENGTH] < 0 || index < state[MAP_LENGTH]; index++) {
      if (read(state[OFFSET]) == CBOR.BREAK) {
        break;
      }

      if ((read(state[OFFSET]) & CBOR.TYPE_MASK) != CBOR.TYPE_TEXT) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      short entryKeyLength = metadataUnsignedInteger();

      requireLength(entryKeyLength);

      boolean matched = entryKeyLength == keyLength;

      if (matched) {
        for (short keyIndex = 0; keyIndex < keyLength; keyIndex++) {
          if (read((short) (state[OFFSET] + keyIndex)) != in[(short) (keyOffset + keyIndex)]) {
            matched = false;
            break;
          }
        }
      }

      state[OFFSET] += entryKeyLength;

      if (matched) {
        return true;
      }

      skip();
    }

    state[OFFSET] = state[MAP_OFFSET];

    return false;
  }

  public boolean key(byte[] key) {
    return key(key, (short) 0, (short) key.length);
  }

  public CBORReader requireKey(byte[] in, short keyOffset, short keyLength) {
    if (!key(in, keyOffset, keyLength)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    return this;
  }

  public CBORReader requireKey(byte[] key) {
    if (!key(key, (short) 0, (short) key.length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    return this;
  }

  public boolean bool() {
    switch (read(state[OFFSET])) {
      case CBOR.FALSE:
        state[OFFSET]++;
        return false;
      case CBOR.TRUE:
        state[OFFSET]++;
        return true;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return false;
    }
  }

  public boolean boolFalse() {
    if (read(state[OFFSET]) != CBOR.FALSE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    state[OFFSET]++;

    return false;
  }

  public boolean boolTrue() {
    if (read(state[OFFSET]) != CBOR.TRUE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    state[OFFSET]++;

    return true;
  }

  public boolean br() {
    if (read(state[OFFSET]) == CBOR.BREAK) {
      state[OFFSET]++;
      return true;
    } else {
      return false;
    }
  }

  public void skip() {
    switch (read(state[OFFSET])) {
      case CBOR.FALSE:
      case CBOR.TRUE:
      case CBOR.BREAK: {
        state[OFFSET]++;
        return;
      }
    }

    switch (read(state[OFFSET]) & CBOR.TYPE_MASK) {
      case CBOR.TYPE_UNSIGNED_INT:
      case CBOR.TYPE_NEGATIVE_INT: {
        short length = metadataBytesLength();
        requireLength(length);
        state[OFFSET] += length;
        break;
      }
      case CBOR.TYPE_BYTES:
      case CBOR.TYPE_TEXT: {
        short length = metadataUnsignedInteger();
        requireLength(length);
        state[OFFSET] += length;
        break;
      }
      case CBOR.TYPE_ARRAY: {
        short length = metadataItemsLength();

        for (short index = 0; length < 0 || index < length; index++) {
          if (br()) {
            if (length < 0) {
              break;
            }

            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          }

          skip();
        }

        break;
      }
      case CBOR.TYPE_MAP: {
        short length = metadataItemsLength();

        for (short index = 0; length < 0 || index < length; index++) {
          if (br()) {
            if (length < 0) {
              break;
            }

            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          }

          skip(); // key
          skip(); // value
        }

        break;
      }
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  private short metadataItemsLength() {
    if ((read(state[OFFSET]) & CBOR.METADATA_MASK) == CBOR.VARIABLE_LENGTH_INDEFINITE_MARK) {
      state[OFFSET]++;
      return -1;
    }

    return metadataUnsignedInteger();
  }

  private short metadataUnsignedInteger() {
    short bytes = metadataBytesLength();

    short value = 0;

    switch (bytes) {
      case 1:
        value = (short) (read(state[OFFSET]) & CBOR.METADATA_MASK);
        break;
      case 2:
        value = (short) (read((short) (state[OFFSET] + 1)) & 0xFF);
        break;
      case 3:
        short high = (short) (read((short) (state[OFFSET] + 1)) & 0xFF);
        short low = (short) (read((short) (state[OFFSET] + 2)) & 0xFF);

        if (high >= 0b10000000) {
          // Exceeded the range of short.
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        value = (short) ((high << 8) | low);
        break;
      default:
        // Exceeded the range of short.
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return -1;
    }

    state[OFFSET] += bytes;

    return value;
  }

  private short metadataBytesLength() {
    short metadata = (short) (read(state[OFFSET]) & CBOR.METADATA_MASK);

    if (metadata <= CBOR.MAX_SIMPLE_UNSIGNED_INT) {
      return 1;
    }

    return (short) (1 + (1 << (metadata & CBOR.METADATA_BYTES_LENGTH_MASK)));
  }
}
