package monoidlib;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class CBORBufferWriter extends CBORWriter {

  protected static final short CHUNK_LENGTH = 256;

  protected final byte[] buffer;
  protected final Object[] chunks;
  private final short overflowStatus;

  public CBORBufferWriter() {
    buffer = null;
    overflowStatus = 0;
    // Cover the nonnegative short offset range without reserving response RAM.
    chunks = new Object[128];
    super.reset((short) 0);
  }

  public CBORBufferWriter(byte[] buffer, short offset, short overflowStatus) {
    this.buffer = buffer;
    this.overflowStatus = overflowStatus;
    chunks = null;
    super.reset(offset);
  }

  public void reset() {
    reset((short) 0);
  }

  @Override
  public void reset(short offset) {
    // The CAP converter requires a declaration here for subclasses calling super.reset(offset).
    super.reset(offset);
  }

  @Override
  public short getLength() {
    // The CAP converter requires a declaration here for subclasses calling super.getLength().
    return super.getLength();
  }

  @Override
  protected void write(short offset, byte value) {
    if (buffer != null) {
      assertLength(offset, (short) 1);
      buffer[offset] = value;
    } else {
      requireChunk(offset)[(short) (offset % CHUNK_LENGTH)] = value;
    }
  }

  @Override
  protected void write(short offset, byte[] data, short dataOffset, short length) {
    if (buffer != null) {
      assertLength(offset, length);
      Util.arrayCopyNonAtomic(data, dataOffset, buffer, offset, length);
      return;
    }

    while (length > 0) {
      byte[] chunk = requireChunk(offset);
      short chunkOffset = (short) (offset % CHUNK_LENGTH);
      short chunkLength = min(length, (short) (CHUNK_LENGTH - chunkOffset));

      Util.arrayCopyNonAtomic(data, dataOffset, chunk, chunkOffset, chunkLength);

      offset += chunkLength;
      dataOffset += chunkLength;
      length -= chunkLength;
    }
  }

  protected byte[] requireChunk(short offset) {
    short index = (short) (offset / CHUNK_LENGTH);
    byte[] chunk = (byte[]) chunks[index];

    if (chunk == null) {
      chunk = createChunk(index);
      chunks[index] = chunk;
    }

    return chunk;
  }

  protected byte[] createChunk(short index) {
    return JCSystem.makeTransientByteArray(CHUNK_LENGTH, JCSystem.CLEAR_ON_DESELECT);
  }

  protected void assertLength(short offset, short length) {
    if (offset > (short) (buffer.length - length)) {
      ISOException.throwIt(overflowStatus);
    }
  }

  public byte[] getDataBuffer() {
    byte[] data = JCSystem.makeTransientByteArray(getLength(), JCSystem.CLEAR_ON_DESELECT);
    copyDataTo(data, (short) 0);
    return data;
  }

  public short copyDataTo(byte[] dest, short destOffset) {
    short length = getLength();

    if (buffer != null) {
      Util.arrayCopyNonAtomic(buffer, (short) (state[OFFSET] - length), dest, destOffset, length);
      return length;
    }

    for (short offset = 0; offset < length; ) {
      byte[] chunk = (byte[]) chunks[(short) (offset / CHUNK_LENGTH)];
      short chunkLength = min((short) (length - offset), CHUNK_LENGTH);

      Util.arrayCopyNonAtomic(chunk, (short) 0, dest, destOffset, chunkLength);

      offset += chunkLength;
      destOffset += chunkLength;
    }

    return length;
  }

  protected static short min(short left, short right) {
    return left < right ? left : right;
  }
}
