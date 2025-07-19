package tests;

import monoid.CBORReader;

class SimpleCBORReader extends CBORReader {
  private byte[] buffer;

  public SimpleCBORReader(byte[] buffer) {
    this.buffer = buffer;

    reset((short) 0);
  }

  @Override
  protected byte[] getBuffer() {
    return buffer;
  }
}
