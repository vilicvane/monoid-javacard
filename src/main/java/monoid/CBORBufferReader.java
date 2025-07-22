package monoid;

public class CBORBufferReader extends CBORReader {

  private byte[] buffer;

  public CBORBufferReader(byte[] buffer) {
    this.buffer = buffer;

    reset((short) 0);
  }

  @Override
  protected byte[] getBuffer() {
    return buffer;
  }
}
