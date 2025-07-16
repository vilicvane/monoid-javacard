package monoid;

import javacard.framework.*;

/**
 * This is an implementation of CBOR subset that might grow with only absolutely
 * necessary features.
 */
public class CBORReader {
  private byte[] buffer;
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

  public void load(byte[] buffer, short offset) {
    this.buffer = buffer;
    this.offset = offset;

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

  public short integer() {
    byte type = (byte) (buffer[offset] & CBOR.TYPE_MASK);

    switch (type) {
      case CBOR.TYPE_UNSIGNED_INT:
      case CBOR.TYPE_NEGATIVE_INT: {
        short value = metadataUnsignedInteger();

        return type == CBOR.TYPE_UNSIGNED_INT ? value : (short) (-value - 1);
      }
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return -1;
    }
  }

  public short bytes(byte[] out, short outOffset) {
    return bytesLike(CBOR.TYPE_BYTES, out, outOffset);
  }

  public short text(byte[] out, short outOffset) {
    return bytesLike(CBOR.TYPE_TEXT, out, outOffset);
  }

  private short bytesLike(byte type, byte[] out, short outOffset) {
    if ((buffer[offset] & CBOR.TYPE_MASK) != type) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short length = metadataUnsignedInteger();

    Util.arrayCopyNonAtomic(buffer, offset, out, outOffset, length);

    offset += length;

    return (short) (outOffset + length);
  }

  public short array() {
    if ((buffer[offset] & CBOR.TYPE_ARRAY) != CBOR.TYPE_ARRAY) {
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
    if ((buffer[offset] & CBOR.TYPE_MAP) != CBOR.TYPE_MAP) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    mapLength = metadataUnsignedInteger();

    mapOffset = offset;

    return mapLength;
  }

  public boolean key(byte[] in, short keyOffset, short keyLength) {
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
    switch (buffer[offset]) {
      case (byte) 0xF4:
        offset++;
        return false;
      case (byte) 0xF5:
        offset++;
        return true;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return false;
    }
  }

  public void next() {
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
    short bytes = metadataBytesLength();

    short value = 0;

    switch (bytes) {
      case 1:
        value = (short) (buffer[offset] & CBOR.METADATA_MASK);
        break;
      case 2:
        value = (short) (buffer[offset + 1] & 0xFF);
        break;
      case 3:
        short high = (short) (buffer[offset + 1] & 0xFF);
        short low = (short) (buffer[offset + 2] & 0xFF);

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
    short metadata = (short) (buffer[offset] & CBOR.METADATA_MASK);

    if (metadata < 0b11000) {
      return 1;
    }

    return (short) (1 + (1 << (metadata & 0b111)));
  }
}
