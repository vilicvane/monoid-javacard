package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class CBORBufferWriter extends CBORWriter {

  private static final short BUFFER_LENGTH_EXTENSION = 256;

  protected byte[] buffer;

  public CBORBufferWriter() {
    reset();
  }

  public void reset() {
    reset((short) 0);
  }

  @Override
  protected void write(short offset, byte value) {
    ensureBufferLength((short) (offset + 1));

    buffer[offset] = value;
  }

  @Override
  protected void write(short offset, byte[] data, short dataOffset, short length) {
    ensureBufferLength((short) (offset + length));

    Util.arrayCopyNonAtomic(data, dataOffset, buffer, offset, length);
  }

  private void ensureBufferLength(short length) {
    short bufferLength = buffer == null ? 0 : (short) buffer.length;

    if (length <= bufferLength) {
      return;
    }

    short extendedLength = (short) (bufferLength + BUFFER_LENGTH_EXTENSION);

    byte[] extendedBuffer = JCSystem.makeTransientByteArray(
      length > extendedLength ? length : extendedLength,
      JCSystem.CLEAR_ON_DESELECT
    );

    if (buffer != null) {
      Util.arrayCopyNonAtomic(buffer, (short) 0, extendedBuffer, (short) 0, bufferLength);

      JCSystem.requestObjectDeletion();
    }

    buffer = extendedBuffer;
  }

  public byte[] getDataBuffer() {
    byte[] data = JCSystem.makeTransientByteArray(getLength(), JCSystem.CLEAR_ON_DESELECT);
    copyDataTo(data, (short) 0);
    return data;
  }

  public short copyDataTo(byte[] dest, short destOffset) {
    short length = getLength();

    if (length > 0) {
      Util.arrayCopyNonAtomic(buffer, (short) 0, dest, destOffset, length);
    }

    return length;
  }
}
