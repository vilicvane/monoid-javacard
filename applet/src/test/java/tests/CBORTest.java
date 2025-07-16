package tests;

import org.junit.*;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;

import monoid.CBORReader;

public class CBORTest {
  @Test
  public void test() {
    byte[] data = Hex.decode(
        "83A362696401646E616D6565416C6963656561646D696EF5A362696402646E616D6563426F626561646D696EF4A362696403646E616D65654361726F6C6561646D696EF5");

    // [
    // { "id": 1, "name": "Alice", "admin": true },
    // { "id": 2, "name": "Bob", "admin": false },
    // { "id": 3, "name": "Carol", "admin": true }
    // ]

    CBORReader cbor = new CBORReader();

    cbor.load(data, (short) 0);

    Assert.assertEquals(cbor.array(), 3);

    cbor.snapshot();

    Assert.assertEquals(cbor.map(), 3);

    cbor.snapshot();

    Assert.assertFalse(cbor.key("xy".getBytes()));
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
    Assert.assertEquals(cbor.integer(), 3);

    cbor.index((short) 1);

    cbor.map();

    Assert.assertTrue(cbor.key("admin".getBytes()));
    Assert.assertEquals(cbor.bool(), false);
  }
}
