package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public abstract class CBORReader implements ByteSource {

  private short offset;

  private short arrayOffset;
  private short mapLength;
  private short mapOffset;

  private static final short MAX_SNAPSHOTS = 8;

  private short[] offsetSnapshots = new short[MAX_SNAPSHOTS];
  private short[] arrayOffsetSnapshots = new short[MAX_SNAPSHOTS];
  private short[] mapLengthSnapshots = new short[MAX_SNAPSHOTS];
  private short[] mapOffsetSnapshots = new short[MAX_SNAPSHOTS];

  private short snapshotIndex = 0;

  protected abstract short getLength();

  public short getOffset() {
    return offset;
  }

  private void requireRange(short offset, short length) {
    if (offset < 0 || length < 0 || offset > (short) (getLength() - length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  private void requireLength(short length) {
    requireRange(offset, length);
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
    this.offset = offset;

    arrayOffset = -1;
    mapOffset = -1;

    resetSnapshot();
  }

  public void snapshot() {
    snapshotIndex++;
    offsetSnapshots[snapshotIndex] = offset;
    arrayOffsetSnapshots[snapshotIndex] = arrayOffset;
    mapLengthSnapshots[snapshotIndex] = mapLength;
    mapOffsetSnapshots[snapshotIndex] = offset;
  }

  public void resetSnapshot() {
    snapshotIndex = 0;
    offsetSnapshots[0] = offset;
    arrayOffsetSnapshots[0] = arrayOffset;
    mapLengthSnapshots[0] = mapLength;
    mapOffsetSnapshots[0] = offset;
  }

  public void popSnapshot(boolean restore) {
    snapshotIndex--;

    if (restore) {
      restore();
    }
  }

  public void popSnapshot() {
    popSnapshot(true);
  }

  public void restore() {
    offset = offsetSnapshots[snapshotIndex];
    arrayOffset = arrayOffsetSnapshots[snapshotIndex];
    mapLength = mapLengthSnapshots[snapshotIndex];
    mapOffset = mapOffsetSnapshots[snapshotIndex];
  }

  public boolean is(byte type) {
    return (read(offset) & CBOR.TYPE_MASK) == type;
  }

  public short integer() {
    byte type = (byte) (read(offset) & CBOR.TYPE_MASK);

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
    if ((read(offset) & CBOR.TYPE_MASK) != type) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short length = metadataUnsignedInteger();

    requireLength(length);

    return length;
  }

  private short bytesLike(byte type, byte[] out, short outOffset) {
    short length = bytesLikeLength(type);

    read(offset, out, outOffset, length);

    offset += length;

    return length;
  }

  private byte[] bytesLike(byte type) {
    short length = bytesLikeLength(type);

    byte[] out = JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);

    read(offset, out, (short) 0, length);

    return out;
  }

  public short array() {
    if ((read(offset) & CBOR.TYPE_MASK) != CBOR.TYPE_ARRAY) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short length = metadataItemsLength();

    arrayOffset = offset;

    return length;
  }

  public boolean index(short index) {
    offset = arrayOffset;

    for (short skipping = 0; skipping <= index; skipping++) {
      if (read(offset) == CBOR.BREAK) {
        break;
      }

      if (skipping == index) {
        return true;
      }

      skip();
    }

    offset = arrayOffset;

    return false;
  }

  public short map() {
    if ((read(offset) & CBOR.TYPE_MASK) != CBOR.TYPE_MAP) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    mapLength = metadataItemsLength();

    mapOffset = offset;

    return mapLength;
  }

  public boolean key(byte[] in, short keyOffset, short keyLength) {
    offset = mapOffset;

    for (short index = 0; mapLength < 0 || index < mapLength; index++) {
      if (read(offset) == CBOR.BREAK) {
        break;
      }

      if ((read(offset) & CBOR.TYPE_MASK) != CBOR.TYPE_TEXT) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      short entryKeyLength = metadataUnsignedInteger();

      requireLength(entryKeyLength);

      boolean matched = entryKeyLength == keyLength;

      if (matched) {
        for (short keyIndex = 0; keyIndex < keyLength; keyIndex++) {
          if (read((short) (offset + keyIndex)) != in[(short) (keyOffset + keyIndex)]) {
            matched = false;
            break;
          }
        }
      }

      offset += entryKeyLength;

      if (matched) {
        return true;
      }

      skip();
    }

    offset = mapOffset;

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
    switch (read(offset)) {
      case CBOR.FALSE:
        offset++;
        return false;
      case CBOR.TRUE:
        offset++;
        return true;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return false;
    }
  }

  public boolean boolFalse() {
    if (read(offset) != CBOR.FALSE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    offset++;

    return false;
  }

  public boolean boolTrue() {
    if (read(offset) != CBOR.TRUE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    offset++;

    return true;
  }

  public boolean br() {
    if (read(offset) == CBOR.BREAK) {
      offset++;
      return true;
    } else {
      return false;
    }
  }

  public void skip() {
    switch (read(offset)) {
      case CBOR.FALSE:
      case CBOR.TRUE:
      case CBOR.BREAK: {
        offset++;
        return;
      }
    }

    switch (read(offset) & CBOR.TYPE_MASK) {
      case CBOR.TYPE_UNSIGNED_INT:
      case CBOR.TYPE_NEGATIVE_INT: {
        short length = metadataBytesLength();
        requireLength(length);
        offset += length;
        break;
      }
      case CBOR.TYPE_BYTES:
      case CBOR.TYPE_TEXT: {
        short length = metadataUnsignedInteger();
        requireLength(length);
        offset += length;
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
    if ((read(offset) & CBOR.METADATA_MASK) == CBOR.VARIABLE_LENGTH_INDEFINITE_MARK) {
      offset++;
      return -1;
    }

    return metadataUnsignedInteger();
  }

  private short metadataUnsignedInteger() {
    short bytes = metadataBytesLength();

    short value = 0;

    switch (bytes) {
      case 1:
        value = (short) (read(offset) & CBOR.METADATA_MASK);
        break;
      case 2:
        value = (short) (read((short) (offset + 1)) & 0xFF);
        break;
      case 3:
        short high = (short) (read((short) (offset + 1)) & 0xFF);
        short low = (short) (read((short) (offset + 2)) & 0xFF);

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

    offset += bytes;

    return value;
  }

  private short metadataBytesLength() {
    short metadata = (short) (read(offset) & CBOR.METADATA_MASK);

    if (metadata <= CBOR.MAX_SIMPLE_UNSIGNED_INT) {
      return 1;
    }

    return (short) (1 + (1 << (metadata & CBOR.METADATA_BYTES_LENGTH_MASK)));
  }
}
