package tests;

import monoid.ByteSource;

public class ByteArraySource implements ByteSource {

  private final byte[][] chunks;
  private final int chunkLength;
  private final int chunkOffset;
  private final int length;

  public ByteArraySource(byte[] data) {
    chunks = new byte[][] { data };
    chunkLength = Math.max(data.length, 1);
    chunkOffset = 0;
    length = data.length;
  }

  public ByteArraySource(byte[] data, int chunkLength, int chunkOffset) {
    this.chunkLength = chunkLength;
    this.chunkOffset = chunkOffset;
    length = data.length;
    chunks = new byte[(length + chunkLength - 1) / chunkLength][];

    for (int index = 0; index < chunks.length; index++) {
      int offset = index * chunkLength;
      int available = Math.min(chunkLength, length - offset);
      chunks[index] = new byte[chunkOffset + available];
      System.arraycopy(data, offset, chunks[index], chunkOffset, available);
    }
  }

  @Override
  public byte[] getChunk(short offset) {
    return chunks[offset / chunkLength];
  }

  @Override
  public short getChunkOffset(short offset) {
    return (short) (chunkOffset + (offset % chunkLength));
  }

  @Override
  public short getChunkLength(short offset) {
    return (short) Math.min(chunkLength - (offset % chunkLength), length - offset);
  }
}
