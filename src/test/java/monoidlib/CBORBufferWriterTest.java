package monoidlib;

import java.util.Arrays;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CBORBufferWriterTest {

  @Test
  public void fixedBufferKeepsItsPrefixAndDoesNotAllocateChunks() {
    byte[] buffer = new byte[16];
    Arrays.fill(buffer, (byte) 0x5A);
    CBORBufferWriter writer = new CBORBufferWriter(buffer, (short) 3, (short) 0x6A84);
    writer.array((short) 2);
    writer.integer((short) 256);
    writer.bool(true);

    Assertions.assertNull(writer.chunks);
    Assertions.assertEquals(5, writer.getLength());
    Assertions.assertArrayEquals(
      new byte[] { (byte) 0x82, 0x19, 1, 0, (byte) 0xF5 },
      writer.getDataBuffer()
    );
    Assertions.assertArrayEquals(new byte[] { 0x5A, 0x5A, 0x5A }, Arrays.copyOf(buffer, 3));
  }

  @Test
  public void fixedBufferReportsItsCallersOverflowStatus() {
    CBORBufferWriter writer = new CBORBufferWriter(new byte[4], (short) 1, (short) 0x1234);
    writer.rawBytes(new byte[] { 1, 2, 3 }, (short) 0, (short) 3);
    Assertions.assertEquals(
      0x1234,
      Assertions.assertThrows(ISOException.class, () -> writer.bool(true)).getReason()
    );
    writer.reset((short) 1);
    Assertions.assertEquals(
      0x1234,
      Assertions.assertThrows(ISOException.class, () ->
        writer.rawBytes(new byte[4], (short) 0, (short) 4)
      ).getReason()
    );
  }

  @Test
  public void dynamicBufferCopiesAcrossEveryChunkBoundaryAndReusesStorage() {
    byte[] data = new byte[1025];
    for (short index = 0; index < data.length; index++) {
      data[index] = (byte) index;
    }
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.rawBytes(data, (short) 0, (short) 255);
    writer.rawBytes(data, (short) 255, (short) 770);
    Assertions.assertArrayEquals(data, writer.getDataBuffer());
    for (short index = 0; index < 5; index++) {
      Assertions.assertEquals(
        JCSystem.CLEAR_ON_DESELECT,
        JCSystem.isTransient(writer.chunks[index])
      );
    }
    Object first = writer.chunks[0];
    writer.reset();
    writer.rawBytes(data, (short) 510, (short) 3);
    Assertions.assertSame(first, writer.chunks[0]);
    Assertions.assertArrayEquals(Arrays.copyOfRange(data, 510, 513), writer.getDataBuffer());
  }
}
