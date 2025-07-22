package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class CBORBufferWriter extends CBORWriter {

  private static final short BUFFER_LENGTH_EXTENSION = 256;

  protected byte[] buffer;

  public CBORBufferWriter() {
    buffer = JCSystem.makeTransientByteArray(BUFFER_LENGTH_EXTENSION, JCSystem.CLEAR_ON_DESELECT);

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
    if (length <= buffer.length) {
      return;
    }

    byte[] extendedBuffer = JCSystem.makeTransientByteArray(
      (short) (buffer.length + BUFFER_LENGTH_EXTENSION),
      JCSystem.CLEAR_ON_DESELECT
    );

    Util.arrayCopyNonAtomic(buffer, (short) 0, extendedBuffer, (short) 0, (short) buffer.length);

    buffer = extendedBuffer;

    JCSystem.requestObjectDeletion();
  }

  public byte[] getData() {
    byte[] data = JCSystem.makeTransientByteArray(getLength(), JCSystem.CLEAR_ON_DESELECT);
    Util.arrayCopyNonAtomic(buffer, (short) 0, data, (short) 0, offset);
    return data;
  }

  public short copyDataTo(byte[] dest, short destOffset) {
    short length = getLength();
    Util.arrayCopyNonAtomic(buffer, (short) 0, dest, destOffset, length);
    return length;
  }
}
