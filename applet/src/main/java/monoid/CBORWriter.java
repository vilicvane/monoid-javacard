package monoid;

import javacard.framework.Util;

public class CBORWriter {
  private byte[] buffer;

  private short initialOffset;
  private short offset;

  public void bind(byte[] buffer, short offset) {
    this.buffer = buffer;
    this.initialOffset = offset;
    this.offset = offset;
  }

  public void unbind() {
    buffer = null;
  }

  public short getLength() {
    return (short) (offset - initialOffset);
  }

  public short copyNonAtomicTo(byte[] out, short outOffset) {
    return Util.arrayCopyNonAtomic(buffer, initialOffset, out, outOffset, getLength());
  }

  public void integer(short value) {
    if (value >= 0) {
      metadataUnsignedInteger(CBOR.TYPE_UNSIGNED_INT, value);
    } else {
      metadataUnsignedInteger(CBOR.TYPE_NEGATIVE_INT, (short) -(value + 1));
    }
  }

  public void bytes(byte[] in, short valueOffset, short valueLength) {
    bytesLike(CBOR.TYPE_BYTES, in, valueOffset, valueLength);
  }

  public void bytes(byte[] value) {
    bytesLike(CBOR.TYPE_BYTES, value, (short) 0, (short) value.length);
  }

  public void text(byte[] in, short valueOffset, short valueLength) {
    bytesLike(CBOR.TYPE_TEXT, in, valueOffset, valueLength);
  }

  public void text(byte[] value) {
    bytesLike(CBOR.TYPE_TEXT, value, (short) 0, (short) value.length);
  }

  private void bytesLike(byte type, byte[] in, short valueOffset, short valueLength) {
    metadataUnsignedInteger(type, valueLength);
    offset = Util.arrayCopyNonAtomic(in, valueOffset, buffer, offset, valueLength);
  }

  public void array(short length) {
    metadataUnsignedInteger(CBOR.TYPE_ARRAY, length);
  }

  public void map(short length) {
    metadataUnsignedInteger(CBOR.TYPE_MAP, length);
  }

  public void bool(boolean value) {
    buffer[offset++] = value ? CBOR.TRUE : CBOR.FALSE;
  }

  public void metadataUnsignedInteger(byte type, short value) {
    if (value <= CBOR.MAX_SIMPLE_UNSIGNED_INT) {
      buffer[offset++] = (byte) (type | value);
    } else if (value <= 0xFF) {
      buffer[offset++] = (byte) (type | CBOR.VARIABLE_LENGTH_UNSIGNED_INT_MARK | 0b000);
      buffer[offset++] = (byte) value;
    } else {
      buffer[offset++] = (byte) (type | CBOR.VARIABLE_LENGTH_UNSIGNED_INT_MARK | 0b001);
      buffer[offset++] = (byte) (value >> 8);
      buffer[offset++] = (byte) value;
    }
  }
}
