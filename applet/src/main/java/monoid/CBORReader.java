package monoid;

import javacard.framework.*;

public abstract class CBORReader {
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

  protected abstract byte[] getBuffer();

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
    byte[] buffer = getBuffer();

    return (buffer[offset] & CBOR.TYPE_MASK) == type;
  }

  public short integer() {
    byte[] buffer = getBuffer();

    byte type = (byte) (buffer[offset] & CBOR.TYPE_MASK);

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

  public short text(byte[] out, short outOffset) {
    return bytesLike(CBOR.TYPE_TEXT, out, outOffset);
  }

  public short text(byte[] out) {
    return bytesLike(CBOR.TYPE_TEXT, out, (short) 0);
  }

  private short bytesLike(byte type, byte[] out, short outOffset) {
    byte[] buffer = getBuffer();

    if ((buffer[offset] & CBOR.TYPE_MASK) != type) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short length = metadataUnsignedInteger();

    Util.arrayCopyNonAtomic(buffer, offset, out, outOffset, length);

    offset += length;

    return (short) (outOffset + length);
  }

  public short array() {
    byte[] buffer = getBuffer();

    if ((buffer[offset] & CBOR.TYPE_MASK) != CBOR.TYPE_ARRAY) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short length = metadataUnsignedInteger();

    arrayOffset = offset;

    return length;
  }

  public void index(short index) {
    offset = arrayOffset;

    for (short skipping = 0; skipping < index; skipping++) {
      next();
    }
  }

  public short map() {
    byte[] buffer = getBuffer();

    if ((buffer[offset] & CBOR.TYPE_MASK) != CBOR.TYPE_MAP) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    mapLength = metadataUnsignedInteger();

    mapOffset = offset;

    return mapLength;
  }

  public boolean key(byte[] in, short keyOffset, short keyLength) {
    byte[] buffer = getBuffer();

    offset = mapOffset;

    for (short index = 0; index < mapLength; index++) {
      if ((buffer[offset] & CBOR.TYPE_MASK) != CBOR.TYPE_TEXT) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      short entryKeyLength = metadataUnsignedInteger();

      boolean matched = entryKeyLength == keyLength && Util.arrayCompare(buffer, offset, in, keyOffset, keyLength) == 0;

      offset += entryKeyLength;

      if (matched) {
        return true;
      }

      next();
    }

    offset = mapOffset;

    return false;
  }

  public boolean key(byte[] key) {
    return key(key, (short) 0, (short) key.length);
  }

  public boolean bool() {
    byte[] buffer = getBuffer();

    switch (buffer[offset]) {
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

  public void next() {
    byte[] buffer = getBuffer();

    switch (buffer[offset]) {
      case CBOR.FALSE:
      case CBOR.TRUE: {
        offset++;
        return;
      }
    }

    switch (buffer[offset] & CBOR.TYPE_MASK) {
      case CBOR.TYPE_UNSIGNED_INT:
      case CBOR.TYPE_NEGATIVE_INT: {
        short length = metadataBytesLength();
        offset += length;
        break;
      }
      case CBOR.TYPE_BYTES:
      case CBOR.TYPE_TEXT: {
        short length = metadataUnsignedInteger();
        offset += length;
        break;
      }
      case CBOR.TYPE_ARRAY: {
        short length = array();

        for (short index = 0; index < length; index++) {
          next();
        }

        break;
      }
      case CBOR.TYPE_MAP: {
        short length = map();

        for (short index = 0; index < length; index++) {
          next(); // key
          next(); // value
        }

        break;
      }
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  private short metadataUnsignedInteger() {
    byte[] buffer = getBuffer();

    short bytes = metadataBytesLength();

    short value = 0;

    switch (bytes) {
      case 1:
        value = (short) (buffer[offset] & CBOR.METADATA_MASK);
        break;
      case 2:
        value = (short) (buffer[(short) (offset + 1)] & 0xFF);
        break;
      case 3:
        short high = (short) (buffer[(short) (offset + 1)] & 0xFF);
        short low = (short) (buffer[(short) (offset + 2)] & 0xFF);

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
    byte[] buffer = getBuffer();

    short metadata = (short) (buffer[offset] & CBOR.METADATA_MASK);

    if (metadata <= CBOR.MAX_SIMPLE_UNSIGNED_INT) {
      return 1;
    }

    return (short) (1 + (1 << (metadata & CBOR.METADATA_BYTES_LENGTH_MASK)));
  }
}
