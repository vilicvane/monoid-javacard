package tests;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import monoid.CBOR;

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

  /**
   * [
   *   { "hello": true, "world": false },
   *   true
   * ]
   */
  private byte[] exampleIndefinite = Hex.decode(
      "9FBF6568656C6C6FF565776F726C64F4FFF5FF");

  @Test
  public void read() {
    SimpleCBORReader cbor = new SimpleCBORReader(example);

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
    SimpleCBORReader cbor = new SimpleCBORReader(exampleIndefinite);

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
    SimpleCBORReader cbor = new SimpleCBORReader(
        Hex.decode("A36461757468A26370696E663838383838386473616665F56370696E663132333435366473616665F4"));

    cbor.map();
    cbor.requireKey("safe".getBytes());
  }

  @Test
  public void write() {
    byte[] buffer = new byte[example.length];

    SimpleCBORWriter cbor = new SimpleCBORWriter(buffer);

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

    Assertions.assertArrayEquals(buffer, example);
  }

  @Test
  public void write_indefinite() {
    byte[] buffer = new byte[exampleIndefinite.length];

    SimpleCBORWriter cbor = new SimpleCBORWriter(buffer);

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

    System.out.println(Hex.toHexString(buffer));

    Assertions.assertArrayEquals(buffer, exampleIndefinite);
  }
}
