package monoid;

public class CBORBufferReader extends CBORReader {

  private byte[] buffer;

  public CBORBufferReader(byte[] buffer) {
    this.buffer = buffer;

    reset((short) 0);
  }

  @Override
  protected short getLength() {
    return (short) buffer.length;
  }

  @Override
  public byte[] getChunk(short offset) {
    return buffer;
  }

  @Override
  public short getChunkOffset(short offset) {
    return offset;
  }

  @Override
  public short getChunkLength(short offset) {
    return (short) (buffer.length - offset);
  }
}
