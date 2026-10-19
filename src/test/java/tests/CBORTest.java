package tests;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import monoid.CBOR;
import monoid.CBORBufferReader;
import monoid.CBORBufferWriter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CBORTest {

  @Test
  public void readEmptyWriterData() {
    CBORBufferWriter writer = new CBORBufferWriter();
    byte[] destination = { 1, 2, 3 };

    Assertions.assertArrayEquals(new byte[0], writer.getDataBuffer());
    Assertions.assertEquals(0, writer.copyDataTo(destination, (short) 1));
    Assertions.assertArrayEquals(new byte[] { 1, 2, 3 }, destination);
  }

  @Test
  public void borrowMessageWithinOriginalBuffer() {
    byte[] request = Hex.decode("a2676d657373616765430102036174f5");
    CBORBufferReader reader = new CBORBufferReader(request);
    reader.map();

    short length = reader.requireKey("message".getBytes()).bytesLength();
    short offset = reader.getOffset();

    Assertions.assertSame(request, reader.getChunk(offset));
    Assertions.assertEquals(offset, reader.getChunkOffset(offset));
    Assertions.assertEquals(request.length - offset, reader.getChunkLength(offset));
    Assertions.assertEquals(3, length);
    Assertions.assertArrayEquals(
      new byte[] { 1, 2, 3 },
      Arrays.copyOfRange(request, offset, offset + length)
    );
    Assertions.assertTrue(reader.requireKey("t".getBytes()).bool());
  }

  @Test
  public void rejectTruncatedBytesBeforeAllocation() {
    CBORBufferReader reader = new CBORBufferReader(Hex.decode("597fff00"));

    ISOException exception = Assertions.assertThrows(ISOException.class, () -> reader.bytes());

    Assertions.assertEquals(ISO7816.SW_WRONG_DATA, exception.getReason());
  }

  @Test
  public void readGlobalByteStrings() {
    byte[] request = Hex.decode("a36161430102036162406174f5");
    CBORBufferReader reader = new CBORBufferReader(request);
    reader.map();

    Assertions.assertArrayEquals(
      new byte[] { 1, 2, 3 },
      reader.requireKey("a".getBytes()).bytesGlobal()
    );
    Assertions.assertArrayEquals(
      new byte[] { 1, 2, 3 },
      reader.requireKey("a".getBytes()).bytesGlobal((short) 3)
    );
    Assertions.assertArrayEquals(new byte[0], reader.requireKey("b".getBytes()).bytesGlobal());
    Assertions.assertTrue(reader.requireKey("t".getBytes()).bool());
    Assertions.assertArrayEquals(Hex.decode("a36161430102036162406174f5"), request);
  }

  @Test
  public void rejectInvalidGlobalByteStrings() {
    CBORBufferReader reader = new CBORBufferReader(Hex.decode("43010203"));
    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      reader.bytesGlobal((short) 2)
    );

    Assertions.assertEquals(ISO7816.SW_WRONG_DATA, exception.getReason());

    for (String request : new String[] { "597fff00", "63010203" }) {
      CBORBufferReader invalid = new CBORBufferReader(Hex.decode(request));
      exception = Assertions.assertThrows(ISOException.class, () -> invalid.bytesGlobal());
      Assertions.assertEquals(ISO7816.SW_WRONG_DATA, exception.getReason());
    }
  }

  @Test
  public void rejectTruncatedSkippedValue() {
    CBORBufferReader reader = new CBORBufferReader(Hex.decode("a2616159040000616200"));
    reader.map();

    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      reader.key("b".getBytes())
    );

    Assertions.assertEquals(ISO7816.SW_WRONG_DATA, exception.getReason());
  }

  /**
   * [
   *   { "id": 1, "name": "Alice", "admin": true },
   *   { "id": 32, "name": "Bob", "admin": false },
   *   { "id": 512, "name": "Carol", "admin": true, "extra": -1 }
   * ]
   */
  private byte[] example = Hex.decode(
    "83A362696401646E616D6565416C6963656561646D696EF5A36269641820646E616D6563426F626561646D696EF4A4626964190200646E616D65654361726F6C6561646D696EF565657874726120"
  );

  /**
   * [
   *   { "hello": true, "world": false },
   *   true
   * ]
   */
  private byte[] exampleIndefinite = Hex.decode("9FBF6568656C6C6FF565776F726C64F4FFF5FF");

  @Test
  public void read() {
    CBORBufferReader cbor = new CBORBufferReader(example);

    Assertions.assertTrue(cbor.is(CBOR.TYPE_ARRAY));
    Assertions.assertFalse(cbor.is(CBOR.TYPE_MAP));

    Assertions.assertEquals(cbor.array(), 3);

    cbor.snapshot();

    Assertions.assertEquals(cbor.map(), 3);

    cbor.snapshot();

    Assertions.assertFalse(cbor.key("xy".getBytes()));

    Assertions.assertTrue(cbor.key("id".getBytes()));
    Assertions.assertEquals(cbor.integer(), 1);

    Assertions.assertTrue(cbor.key("name".getBytes()));

    byte[] text = new byte[5];

    Assertions.assertEquals(cbor.text(text, (short) 0), 5);
    Assertions.assertArrayEquals(text, "Alice".getBytes());

    Assertions.assertTrue(cbor.key("admin".getBytes()));
    Assertions.assertEquals(cbor.bool(), true);

    Assertions.assertTrue(cbor.key("id".getBytes()));
    Assertions.assertEquals(cbor.integer(), 1);

    cbor.popSnapshot();

    cbor.index((short) 2);
    cbor.map();

    Assertions.assertTrue(cbor.key("id".getBytes()));
    Assertions.assertEquals(cbor.integer(), 512);

    Assertions.assertTrue(cbor.key("extra".getBytes()));
    Assertions.assertEquals(cbor.integer(), -1);

    cbor.index((short) 1);
    cbor.map();

    Assertions.assertTrue(cbor.key("id".getBytes()));
    Assertions.assertEquals(cbor.integer(), 32);

    Assertions.assertTrue(cbor.key("admin".getBytes()));
    Assertions.assertEquals(cbor.bool(), false);
  }

  @Test
  public void read_indefinite() {
    CBORBufferReader cbor = new CBORBufferReader(exampleIndefinite);

    Assertions.assertEquals(cbor.array(), -1);

    Assertions.assertEquals(cbor.map(), -1);

    Assertions.assertTrue(cbor.key("hello".getBytes()));
    Assertions.assertEquals(cbor.bool(), true);

    Assertions.assertTrue(cbor.key("world".getBytes()));
    Assertions.assertEquals(cbor.bool(), false);

    Assertions.assertTrue(cbor.br());

    Assertions.assertFalse(cbor.br());

    Assertions.assertTrue(cbor.bool());

    Assertions.assertTrue(cbor.br());
  }

  @Test
  public void read_1() {
    CBORBufferReader cbor = new CBORBufferReader(
      Hex.decode(
        "A36461757468A26370696E663838383838386473616665F56370696E663132333435366473616665F4"
      )
    );

    cbor.map();
    cbor.requireKey("safe".getBytes());
  }

  @Test
  public void write() {
    CBORBufferWriter cbor = new CBORBufferWriter();

    cbor.array((short) 3);
    {
      cbor.map((short) 3);
      {
        cbor.text("id".getBytes());
        cbor.integer((short) 1);

        cbor.text("name".getBytes());
        cbor.text("Alice".getBytes());

        cbor.text("admin".getBytes());
        cbor.bool(true);
      }

      cbor.map((short) 3);
      {
        cbor.text("id".getBytes());
        cbor.integer((short) 32);

        cbor.text("name".getBytes());
        cbor.text("Bob".getBytes());

        cbor.text("admin".getBytes());
        cbor.bool(false);
      }

      cbor.map((short) 4);
      {
        cbor.text("id".getBytes());
        cbor.integer((short) 512);

        cbor.text("name".getBytes());
        cbor.text("Carol".getBytes());

        cbor.text("admin".getBytes());
        cbor.bool(true);

        cbor.text("extra".getBytes());
        cbor.integer((short) -1);
      }
    }

    Assertions.assertArrayEquals(cbor.getDataBuffer(), example);
  }

  @Test
  public void write_indefinite() {
    CBORBufferWriter cbor = new CBORBufferWriter();

    cbor.array();
    {
      cbor.map();
      {
        cbor.text("hello".getBytes());
        cbor.bool(true);

        cbor.text("world".getBytes());
        cbor.bool(false);

        cbor.br();
      }

      cbor.bool(true);

      cbor.br();
    }

    byte[] buffer = cbor.getDataBuffer();

    System.out.println(Hex.toHexString(buffer));

    Assertions.assertArrayEquals(buffer, exampleIndefinite);
  }
}
