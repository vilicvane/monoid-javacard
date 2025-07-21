package tests;

import java.util.Arrays;
import javacard.framework.Util;
import monoid.CBORWriter;

public class SimpleCBORWriter extends CBORWriter {

  private byte[] buffer;

  public SimpleCBORWriter(byte[] buffer) {
    this.buffer = buffer;
    reset((short) 0);
  }

  public SimpleCBORWriter(short bufferSize) {
    this(new byte[bufferSize]);
  }

  public SimpleCBORWriter() {
    this(new byte[256]);
  }

  @Override
  protected void write(short offset, byte value) {
    buffer[offset] = value;
  }

  @Override
  protected void write(short offset, byte[] buffer, short bufferOffset, short length) {
    Util.arrayCopyNonAtomic(buffer, bufferOffset, this.buffer, offset, length);
  }

  public byte[] getData() {
    return Arrays.copyOf(buffer, getLength());
  }
}
