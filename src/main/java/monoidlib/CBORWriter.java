package monoidlib;

import javacard.framework.JCSystem;

public abstract class CBORWriter {

  private static final short INITIAL_OFFSET = 0;
  protected static final short OFFSET = 1;

  protected final short[] state = JCSystem.makeTransientShortArray(
    (short) 2,
    JCSystem.CLEAR_ON_DESELECT
  );

  protected abstract void write(short offset, byte value);

  protected abstract void write(short offset, byte[] buffer, short bufferOffset, short length);

  public void reset(short offset) {
    state[INITIAL_OFFSET] = offset;
    state[OFFSET] = offset;
  }

  public short getLength() {
    return (short) (state[OFFSET] - state[INITIAL_OFFSET]);
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

  /** Starts one byte string whose content is subsequently written with rawBytes. */
  public void bytesLength(short length) {
    metadataUnsignedInteger(CBOR.TYPE_BYTES, length);
  }

  public void rawBytes(byte[] in, short valueOffset, short valueLength) {
    write(state[OFFSET], in, valueOffset, valueLength);

    state[OFFSET] += valueLength;
  }

  public void text(byte[] in, short valueOffset, short valueLength) {
    bytesLike(CBOR.TYPE_TEXT, in, valueOffset, valueLength);
  }

  public void text(byte[] value) {
    bytesLike(CBOR.TYPE_TEXT, value, (short) 0, (short) value.length);
  }

  private void bytesLike(byte type, byte[] in, short valueOffset, short valueLength) {
    metadataUnsignedInteger(type, valueLength);
    rawBytes(in, valueOffset, valueLength);
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
    write(state[OFFSET]++, value ? CBOR.TRUE : CBOR.FALSE);
  }

  public void br() {
    write(state[OFFSET]++, CBOR.BREAK);
  }

  public static short metadataLength(short value) {
    return value <= CBOR.MAX_SIMPLE_UNSIGNED_INT ? (short) 1 : value <= 0xFF ? (short) 2 : 3;
  }

  private void metadataUnsignedInteger(byte type, short value) {
    if (value <= CBOR.MAX_SIMPLE_UNSIGNED_INT) {
      write(state[OFFSET]++, (byte) (type | value));
    } else if (value <= 0xFF) {
      write(state[OFFSET]++, (byte) (type | CBOR.VARIABLE_LENGTH_UNSIGNED_INT_MARK | 0b000));
      write(state[OFFSET]++, (byte) value);
    } else {
      write(state[OFFSET]++, (byte) (type | CBOR.VARIABLE_LENGTH_UNSIGNED_INT_MARK | 0b001));
      write(state[OFFSET]++, (byte) (value >> 8));
      write(state[OFFSET]++, (byte) value);
    }
  }

  private void metadataIndefinite(byte type) {
    write(state[OFFSET]++, (byte) (type | CBOR.VARIABLE_LENGTH_INDEFINITE_MARK));
  }
}
