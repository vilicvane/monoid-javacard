package monoid;

public abstract class CBORWriter {

  protected short initialOffset;
  protected short offset;

  protected abstract void write(short offset, byte value);

  protected abstract void write(
    short offset,
    byte[] buffer,
    short bufferOffset,
    short length
  );

  protected void reset(short offset) {
    this.initialOffset = offset;
    this.offset = offset;
  }

  public short getLength() {
    return (short) (offset - initialOffset);
  }

  public void integer(short value) {
    if (value >= 0) {
      metadataUnsignedInteger(CBOR.TYPE_UNSIGNED_INT, value);
    } else {
      metadataUnsignedInteger(
        CBOR.TYPE_NEGATIVE_INT,
        (short) -(short) (value + 1)
      );
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

  private void bytesLike(
    byte type,
    byte[] in,
    short valueOffset,
    short valueLength
  ) {
    metadataUnsignedInteger(type, valueLength);

    write(offset, in, valueOffset, valueLength);

    offset += valueLength;
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
    write(offset++, value ? CBOR.TRUE : CBOR.FALSE);
  }

  public void br() {
    write(offset++, CBOR.BREAK);
  }

  private void metadataUnsignedInteger(byte type, short value) {
    if (value <= CBOR.MAX_SIMPLE_UNSIGNED_INT) {
      write(offset++, (byte) (type | value));
    } else if (value <= 0xFF) {
      write(
        offset++,
        (byte) (type | CBOR.VARIABLE_LENGTH_UNSIGNED_INT_MARK | 0b000)
      );
      write(offset++, (byte) value);
    } else {
      write(
        offset++,
        (byte) (type | CBOR.VARIABLE_LENGTH_UNSIGNED_INT_MARK | 0b001)
      );
      write(offset++, (byte) (value >> 8));
      write(offset++, (byte) value);
    }
  }

  private void metadataIndefinite(byte type) {
    write(offset++, (byte) (type | CBOR.VARIABLE_LENGTH_INDEFINITE_MARK));
  }
}
