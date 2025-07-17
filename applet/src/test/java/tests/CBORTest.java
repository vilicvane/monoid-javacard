package tests;

import org.junit.*;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import monoid.CBOR;
import monoid.CBORReader;
import monoid.CBORWriter;

public class CBORTest {
  /**
   * [
   *   { "id": 1, "name": "Alice", "admin": true },
   *   { "id": 32, "name": "Bob", "admin": false },
   *   { "id": 512, "name": "Carol", "admin": true, "extra": -1 }
   * ]
   */
  private byte[] example = Hex.decode(
      "83A362696401646E616D6565416C6963656561646D696EF5A36269641820646E616D6563426F626561646D696EF4A4626964190200646E616D65654361726F6C6561646D696EF565657874726120");

  @Test
  public void read() {
    TestCBORReader cbor = new TestCBORReader(example);

    Assert.assertTrue(cbor.is(CBOR.TYPE_ARRAY));
    Assert.assertFalse(cbor.is(CBOR.TYPE_MAP));

    Assert.assertEquals(cbor.array(), 3);

    cbor.snapshot();

    Assert.assertEquals(cbor.map(), 3);

    cbor.snapshot();

    Assert.assertFalse(cbor.key("xy".getBytes()));

    Assert.assertTrue(cbor.key("id".getBytes()));
    Assert.assertEquals(cbor.integer(), 1);

    Assert.assertTrue(cbor.key("name".getBytes()));

    byte[] text = new byte[5];

    Assert.assertEquals(cbor.text(text, (short) 0), 5);
    Assert.assertArrayEquals(text, "Alice".getBytes());

    Assert.assertTrue(cbor.key("admin".getBytes()));
    Assert.assertEquals(cbor.bool(), true);

    Assert.assertTrue(cbor.key("id".getBytes()));
    Assert.assertEquals(cbor.integer(), 1);

    cbor.popSnapshot();

    cbor.index((short) 2);
    cbor.map();

    Assert.assertTrue(cbor.key("id".getBytes()));
    Assert.assertEquals(cbor.integer(), 512);

    Assert.assertTrue(cbor.key("extra".getBytes()));
    Assert.assertEquals(cbor.integer(), -1);

    cbor.index((short) 1);
    cbor.map();

    Assert.assertTrue(cbor.key("id".getBytes()));
    Assert.assertEquals(cbor.integer(), 32);

    Assert.assertTrue(cbor.key("admin".getBytes()));
    Assert.assertEquals(cbor.bool(), false);
  }

  @Test
  public void write() {
    byte[] buffer = new byte[example.length];

    TestCBORWriter cbor = new TestCBORWriter(buffer);

    cbor.array((short) 3);

    cbor.map((short) 3);

    cbor.text("id".getBytes());
    cbor.integer((short) 1);

    cbor.text("name".getBytes());
    cbor.text("Alice".getBytes());

    cbor.text("admin".getBytes());
    cbor.bool(true);

    cbor.map((short) 3);

    cbor.text("id".getBytes());
    cbor.integer((short) 32);

    cbor.text("name".getBytes());
    cbor.text("Bob".getBytes());

    cbor.text("admin".getBytes());
    cbor.bool(false);

    cbor.map((short) 4);

    cbor.text("id".getBytes());
    cbor.integer((short) 512);

    cbor.text("name".getBytes());
    cbor.text("Carol".getBytes());

    cbor.text("admin".getBytes());
    cbor.bool(true);

    cbor.text("extra".getBytes());
    cbor.integer((short) -1);

    Assert.assertArrayEquals(buffer, example);
  }
}

class TestCBORReader extends CBORReader {
  private byte[] buffer;

  public TestCBORReader(byte[] buffer) {
    this.buffer = buffer;

    reset((short) 0);
  }

  @Override
  protected byte[] getBuffer() {
    return buffer;
  }
}

class TestCBORWriter extends CBORWriter {
  private byte[] buffer;

  public TestCBORWriter(byte[] buffer) {
    this.buffer = buffer;

    reset((short) 0);
  }

  @Override
  protected byte[] getBuffer() {
    return buffer;
  }
}
