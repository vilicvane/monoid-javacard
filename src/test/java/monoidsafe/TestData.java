package monoidsafe;

import javacard.framework.JCSystem;
import org.junit.jupiter.api.Assertions;

class TestData implements SafeDataShareable {

  private final byte[] data;
  private byte[] readBuffer;
  int readCount;

  TestData(byte[] data) {
    this.data = data;
  }

  @Override
  public short getLength() {
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
    return (short) data.length;
  }

  @Override
  public void read(short dataOffset, byte[] buffer, short offset, short length) {
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
    Assertions.assertTrue(buffer.length <= 256);

    if (readBuffer == null) {
      readBuffer = buffer;
    } else {
      Assertions.assertSame(readBuffer, buffer);
    }

    readCount++;
    System.arraycopy(data, dataOffset, buffer, offset, length);
  }

  static byte[] read(SafeDataShareable source) {
    byte[] data = new byte[source.getLength()];
    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      (short) Math.min(256, data.length)
    );

    for (int offset = 0; offset < data.length; offset += buffer.length) {
      int length = Math.min(buffer.length, data.length - offset);
      source.read((short) offset, buffer, (short) 0, (short) length);
      System.arraycopy(buffer, 0, data, offset, length);
    }

    return data;
  }
}
