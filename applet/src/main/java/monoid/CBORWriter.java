package monoid;

import javacard.framework.*;

public abstract class CBORWriter {
  private short initialOffset;
  private short offset;

  protected abstract byte[] getBuffer();

  protected void reset(short offset) {
    this.initialOffset = offset;
    this.offset = offset;
  }

  public short getLength() {
    return (short) (offset - initialOffset);
  }

  public short copyNonAtomicTo(byte[] out, short outOffset) {
    byte[] buffer = getBuffer();

    return Util.arrayCopyNonAtomic(buffer, initialOffset, out, outOffset, getLength());
  }

  public void integer(short value) {
    if (value >= 0) {
      metadataUnsignedInteger(CBOR.TYPE_UNSIGNED_INT, value);
    } else {
      metadataUnsignedInteger(CBOR.TYPE_NEGATIVE_INT, (short) -(short) (value + 1));
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
    byte[] buffer = getBuffer();

    metadataUnsignedInteger(type, valueLength);

    offset = Util.arrayCopyNonAtomic(in, valueOffset, buffer, offset, valueLength);
  }

  public void array(short length) {
    metadataUnsignedInteger(CBOR.TYPE_ARRAY, length);
  }

  public void array() {
    metadataIndefinite(CBOR.TYPE_ARRAY);
  }

  public void map(short length) {
    metadataUnsignedInteger(CBOR.TYPE_MAP, length);
  }

  public void map() {
    metadataIndefinite(CBOR.TYPE_MAP);
  }

  public void bool(boolean value) {
    byte[] buffer = getBuffer();

    buffer[offset++] = value ? CBOR.TRUE : CBOR.FALSE;
  }

  public void br() {
    byte[] buffer = getBuffer();

    buffer[offset++] = CBOR.BREAK;
  }

  private void metadataUnsignedInteger(byte type, short value) {
    byte[] buffer = getBuffer();

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

  private void metadataIndefinite(byte type) {
    byte[] buffer = getBuffer();

    buffer[offset++] = (byte) (type | CBOR.VARIABLE_LENGTH_INDEFINITE_MARK);
  }
}
