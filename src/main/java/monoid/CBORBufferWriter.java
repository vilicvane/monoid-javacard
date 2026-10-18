package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class CBORBufferWriter extends CBORWriter {

  protected static final short CHUNK_LENGTH = 256;

  // Cover the nonnegative short offset range without reserving response RAM.
  protected final Object[] chunks = new Object[128];

  public CBORBufferWriter() {
    reset();
  }

  public void reset() {
    reset((short) 0);
  }

  @Override
  protected void write(short offset, byte value) {
    requireChunk(offset)[(short) (offset % CHUNK_LENGTH)] = value;
  }

  @Override
  protected void write(short offset, byte[] data, short dataOffset, short length) {
    while (length > 0) {
      byte[] chunk = requireChunk(offset);
      short chunkOffset = (short) (offset % CHUNK_LENGTH);
      short chunkLength = Utils.min(length, (short) (CHUNK_LENGTH - chunkOffset));

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

  public byte[] getDataBuffer() {
    byte[] data = JCSystem.makeTransientByteArray(getLength(), JCSystem.CLEAR_ON_DESELECT);
    copyDataTo(data, (short) 0);
    return data;
  }

  public short copyDataTo(byte[] dest, short destOffset) {
    short length = getLength();

    for (short offset = 0; offset < length; ) {
      byte[] chunk = (byte[]) chunks[(short) (offset / CHUNK_LENGTH)];
      short chunkLength = Utils.min((short) (length - offset), CHUNK_LENGTH);

      Util.arrayCopyNonAtomic(chunk, (short) 0, dest, destOffset, chunkLength);

      offset += chunkLength;
      destOffset += chunkLength;
    }

    return length;
  }
}
