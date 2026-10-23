package monoid;

import com.licel.jcardsim.base.ApduCase;
import javacard.framework.JCSystem;
import main.ShareableSimulatorRuntime;
import org.junit.jupiter.api.Assertions;

class TestData implements SafeDataSource {

  static class Runtime extends ShareableSimulatorRuntime {

    void beginCommand() {
      // Direct unit tests call internal methods outside process(); give those calls the
      // APDU context available during a real command without bypassing SIO checks.
      activateSimulatorRuntimeInstance();
      resetAPDU(getCurrentAPDU(), ApduCase.Case1, new byte[] { 0, 0, 0, 0 });
    }
  }

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
    // Reads stay bounded even when the destination is the complete persistent array.
    Assertions.assertTrue(length <= 256);

    if (readBuffer == null) {
      readBuffer = buffer;
    } else {
      Assertions.assertSame(readBuffer, buffer);
    }

    readCount++;
    System.arraycopy(data, dataOffset, buffer, offset, length);
  }

  static byte[] read(SafeDataSource source) {
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
