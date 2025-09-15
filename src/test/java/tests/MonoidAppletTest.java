package tests;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.utils.AIDUtil;
import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import java.io.IOException;
import java.util.HashMap;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoid.CBORBufferReader;
import monoid.CBORBufferWriter;
import monoid.Command;
import monoid.MonoidApplet;
import monoid.Safe;
import monoid.SafeException;
import monoidsafe.MonoidSafeApplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@ExtendWith(BailExtension.class)
public class MonoidAppletTest extends AppletTest {

  private static final AID MONOID_SAFE_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_AID}}"
    "f06d6f6e6f696400010000"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f696401010000"
  );

  private static final byte[] SAFE_PIN = "888888".getBytes();
  private static final byte[] PIN = "123456".getBytes();

  private static final byte[] TEST_SEED = Hex.decode(
    "3100314ef25741e991c7bea11a7542b31d873d45a4b6c3da120d8a60553095ddc9a72a1a46e397495402ab9a2fa1190d62d07480275dc91faf12187d46aa0b63"
  );
  private static final byte[] TEST_SEED_INDEX = Hex.decode("0240" + "7e083e348d6eb20e");

  private static final byte[] TEST_MASTER = Hex.decode(
    "5857033b6a5b148e096d2548438cc984b15a5c6590476ae4c12360718ef056c05926524c3889eeccfaaca9805ca83bec6038e01557ca41d11329879b64eb9089"
  );
  private static final byte[] TEST_MASTER_INDEX = Hex.decode("0320" + "aa169eed841d5f74");

  private static final byte[] TEST_SECP256K1_KEY = Hex.decode(
    "eff3af6963c58a7a8ad2462bd41486d0a146d8850bd497234da6d419041f4c58"
  );
  private static final byte[] TEST_SECP256K1_KEY_INDEX = Hex.decode("0401" + "b5519fdc940daeb3");

  private static final byte[] TEST_DIGEST = Hex.decode(
    "43ddcab065bcc7bd8d80c479ed29d3658ccf3ac3343b7044013008bde5ca19cf"
  );

  // m/44'/60'/0'/0/0
  private static final byte[] TEST_PATH = Hex.decode("8000002c8000003c800000000000000000000000");

  private static final byte[] TEST_SEED_DERIVED_PUBLIC_KEY = Hex.decode(
    "0332066e8d312abcaaf8fea7b2c4f5065410c07b315bde3229f778021b2e763912"
  );
  private static final byte[] TEST_SEED_DERIVED_CHAIN_CODE = Hex.decode(
    "78307a5fbe683c88809756308869b1e36790820c8a6e6552e1ad848eddbbb8ae"
  );

  private static final byte[] TEST_MASTER_DERIVED_PUBLIC_KEY = Hex.decode(
    "02541cfc913dc568120034e040063f39933ca6965ac6cbd5e41f5a0c641ace57d3"
  );
  private static final byte[] TEST_MASTER_DERIVED_CHAIN_CODE = Hex.decode(
    "2ff847394908fdc40c3b30c094f07df6ba5bbb1ac5cac1c978b46434ccffacce"
  );

  private static final byte[] TEST_SECP256K1_DERIVED_PUBLIC_KEY = Hex.decode(
    "031df0b7bb633f1559b9c17d740a8a42d7f6cc3e79e2cefb27093954885e9e13df"
  );

  public MonoidAppletTest() {
    super(
      MONOID_AID,
      System.getenv("CARD_TYPE") != null && System.getenv("CARD_TYPE").equals("physical")
        ? CardType.PHYSICAL
        : CardType.JCARDSIMLOCAL
    );
    if (simulator != null) {
      simulator.installApplet(MONOID_SAFE_AID, MonoidSafeApplet.class);
      simulator.installApplet(MONOID_AID, MonoidApplet.class);
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(1)
  public void firstHello() throws Exception {
    CBORBufferWriter cbor = new CBORBufferWriter();

    cbor.map((short) 0);

    CommandAPDU request = apdu(0x00, 0x20, 0, 0, cbor.getDataBuffer());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);

    CBORBufferReader reader = new CBORBufferReader(response.getBytes());
    reader.map();
    {
      Assertions.assertEquals(4, reader.requireKey("id".getBytes()).bytes().length);
      Assertions.assertFalse(reader.requireKey("pin".getBytes()).bool());

      reader.requireKey("safe".getBytes()).map();
      {
        Assertions.assertEquals(4, reader.requireKey("id".getBytes()).bytes().length);
        Assertions.assertFalse(reader.requireKey("pin".getBytes()).bool());
      }
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(2)
  public void systemInformation() throws Exception {
    CBORBufferWriter cbor = new CBORBufferWriter();

    cbor.map((short) 0);

    CommandAPDU request = apdu(0x00, 0x2F, 0, 0, cbor.getDataBuffer());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);

    CBORBufferReader reader = new CBORBufferReader(response.getBytes());
    reader.map();
    {
      reader.requireKey("versions".getBytes());
      reader.requireKey("memories".getBytes());
      reader.requireKey("features".getBytes());
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(3)
  public void setSafePIN() throws Exception {
    CBORBufferWriter writer = new CBORBufferWriter();

    writer.map((short) 2);
    {
      writer.text("pin".getBytes());
      writer.text(SAFE_PIN);

      writer.text("safe".getBytes());
      writer.bool(true);
    }

    CommandAPDU request = apdu(0x00, 0x21, 0, 0, writer.getDataBuffer());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(4)
  public void setPIN() throws Exception {
    CBORBufferWriter writer = new CBORBufferWriter();

    writer.map((short) 2);
    {
      writeAuth(writer, true);

      writer.text("pin".getBytes());
      writer.text(PIN);
    }

    CommandAPDU request = apdu(0x00, 0x21, 0, 0, writer.getDataBuffer());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(5)
  public void secondHello() throws Exception {
    CBORBufferWriter cbor = new CBORBufferWriter();

    cbor.map((short) 0);

    CommandAPDU request = apdu(0x00, 0x20, 0, 0, cbor.getDataBuffer());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);

    CBORBufferReader reader = new CBORBufferReader(response.getBytes());
    reader.map();
    {
      Assertions.assertTrue(reader.requireKey("pin".getBytes()).integer() > 0);

      reader.requireKey("safe".getBytes()).map();
      {
        Assertions.assertTrue(reader.requireKey("pin".getBytes()).integer() > 0);
      }
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(6)
  public void unlockSafe() throws Exception {
    CBORBufferWriter writer = new CBORBufferWriter();

    writer.map((short) 3);
    {
      writeAuth(writer, true);

      writer.text("pin".getBytes());
      writer.text(SAFE_PIN);

      writer.text("safe".getBytes());
      writer.bool(true);
    }

    CommandAPDU request = apdu(0x00, 0x21, 0, 0, writer.getDataBuffer());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(7)
  public void createRandomKeys() throws Exception {
    byte[][] types = {
      Safe.TYPE_TEXT_ENTROPY,
      Safe.TYPE_TEXT_ENTROPY,
      Safe.TYPE_TEXT_SEED,
      Safe.TYPE_TEXT_SEED,
      Safe.TYPE_TEXT_MASTER,
      Safe.TYPE_TEXT_SECP256K1,
    };

    short[] lengths = { 32, 48, 64, 128, 32, 0 };

    for (int index = 0; index < types.length; index++) {
      byte[] type = types[index];
      short length = lengths[index];

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) (length == 0 ? 2 : 3));
      {
        writeAuth(writer, false);

        writer.text("type".getBytes());
        writer.text(type);

        if (length > 0) {
          writer.text("length".getBytes());
          writer.integer(length);
        }
      }

      CommandAPDU request = apdu(0x00, 0x38, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      CBORBufferReader reader = new CBORBufferReader(response.getBytes());
      reader.map();
      {
        reader.requireKey("index".getBytes()).bytes();
      }
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(8)
  public void createSetViewGetRemove() throws Exception {
    byte[] index = "some index".getBytes(); // "coincidentally" 10 bytes
    byte[] alias = "some alias".getBytes();
    byte[] data = "some data".getBytes();

    {
      // create

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 3);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(index);

        writer.text("data".getBytes());
        writer.bytes(data);
      }

      CommandAPDU request = apdu(0x00, 0x34, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      CBORBufferReader reader = new CBORBufferReader(response.getBytes());
      reader.map();
      {
        Assertions.assertArrayEquals(index, reader.requireKey("index".getBytes()).bytes());
      }
    }

    {
      // set

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 3);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(index);

        writer.text("alias".getBytes());
        writer.text(alias);
      }

      CommandAPDU request = apdu(0x00, 0x33, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);
    }

    {
      // view

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 2);
      {
        writeAuth(writer, true);

        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x31, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      CBORBufferReader reader = new CBORBufferReader(response.getBytes());
      reader.map();
      {
        Assertions.assertArrayEquals(alias, reader.requireKey("alias".getBytes()).text());
        Assertions.assertFalse(reader.key("data".getBytes()));
      }
    }

    {
      // get

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 2);
      {
        writeAuth(writer, true);

        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x32, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      CBORBufferReader reader = new CBORBufferReader(response.getBytes());
      reader.map();
      {
        Assertions.assertArrayEquals(alias, reader.requireKey("alias".getBytes()).text());
        Assertions.assertArrayEquals(data, reader.requireKey("data".getBytes()).bytes());
      }
    }

    {
      // remove

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 2);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x35, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);
    }

    {
      // get

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 2);
      {
        writeAuth(writer, true);

        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x32, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertError(response, SafeException.CODE_NOT_FOUND);
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(9)
  public void addTestKeys() throws Exception {
    HashMap<byte[], byte[]> keys = new HashMap<>();

    keys.put(TEST_SEED_INDEX, TEST_SEED);
    keys.put(TEST_MASTER_INDEX, TEST_MASTER);
    keys.put(TEST_SECP256K1_KEY_INDEX, TEST_SECP256K1_KEY);

    for (HashMap.Entry<byte[], byte[]> entry : keys.entrySet()) {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 3);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(entry.getKey());

        writer.text("data".getBytes());
        writer.bytes(entry.getValue());
      }

      CommandAPDU request = apdu(0x00, 0x34, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(10)
  public void list() throws Exception {
    CBORBufferWriter writer = new CBORBufferWriter();

    CardManager manager = connect();

    writer.map((short) 1);
    {
      writeAuth(writer, false);
    }

    byte[] buffer;

    if (simulator == null) {
      CommandAPDU request = apdu(0x00, 0x30, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

      // The middleman already handles chunked responses for physical cards.

      buffer = response.getBytes();

      assertNoError(response);
    } else {
      buffer = new byte[1024];

      int offset = 0;

      {
        CommandAPDU request = apdu(0x00, 0x30, 0, 0, writer.getDataBuffer());

        ResponseAPDU response = manager.transmit(request);

        int length = response.getBytes().length - 2;

        System.arraycopy(response.getBytes(), 0, buffer, offset, length);

        offset += length;

        Assertions.assertEquals(0x6100, response.getSW() & 0xFF00);
      }

      {
        CommandAPDU request = apdu(0x00, 0xC0, 0, 0);

        ResponseAPDU response = manager.transmit(request);

        int length = response.getBytes().length;

        System.arraycopy(response.getBytes(), 0, buffer, offset, length);

        offset += length;

        assertNoError(buffer);
      }
    }

    CBORBufferReader reader = new CBORBufferReader(buffer);
    reader.map();
    {
      Assertions.assertEquals(9, reader.requireKey("items".getBytes()).array());

      Assertions.assertTrue(reader.index((short) 8));
      reader.map();
      {
        reader.requireKey("type".getBytes()).text();
        reader.requireKey("index".getBytes()).bytes();
      }
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(11)
  public void viewKeys() throws Exception {
    {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 5);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(TEST_SEED_INDEX);

        writer.text("curve".getBytes());
        writer.text("secp256k1".getBytes());

        writer.text("seed".getBytes());
        writer.text("Bitcoin seed".getBytes());

        writer.text("path".getBytes());
        writer.bytes(TEST_PATH);
      }

      CommandAPDU request = apdu(0x00, 0x40, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      CBORBufferReader reader = new CBORBufferReader(response.getBytes());

      reader.map();
      {
        Assertions.assertArrayEquals(
          reader.requireKey("publicKey".getBytes()).bytes(),
          TEST_SEED_DERIVED_PUBLIC_KEY
        );
        Assertions.assertArrayEquals(
          reader.requireKey("chainCode".getBytes()).bytes(),
          TEST_SEED_DERIVED_CHAIN_CODE
        );
      }
    }

    {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 4);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(TEST_MASTER_INDEX);

        writer.text("curve".getBytes());
        writer.text("secp256k1".getBytes());

        writer.text("path".getBytes());
        writer.bytes(TEST_PATH);
      }

      CommandAPDU request = apdu(0x00, 0x40, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      CBORBufferReader reader = new CBORBufferReader(response.getBytes());

      reader.map();
      {
        Assertions.assertArrayEquals(
          reader.requireKey("publicKey".getBytes()).bytes(),
          TEST_MASTER_DERIVED_PUBLIC_KEY
        );
        Assertions.assertArrayEquals(
          reader.requireKey("chainCode".getBytes()).bytes(),
          TEST_MASTER_DERIVED_CHAIN_CODE
        );
      }
    }

    {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 3);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(TEST_SECP256K1_KEY_INDEX);

        writer.text("curve".getBytes());
        writer.text("secp256k1".getBytes());
      }

      CommandAPDU request = apdu(0x00, 0x40, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      CBORBufferReader reader = new CBORBufferReader(response.getBytes());

      reader.map();
      {
        Assertions.assertArrayEquals(
          reader.requireKey("publicKey".getBytes()).bytes(),
          TEST_SECP256K1_DERIVED_PUBLIC_KEY
        );
      }
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(12)
  public void sign() throws Exception {
    {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 7);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(TEST_SEED_INDEX);

        writer.text("curve".getBytes());
        writer.text("secp256k1".getBytes());

        writer.text("seed".getBytes());
        writer.text("Bitcoin seed".getBytes());

        writer.text("path".getBytes());
        writer.bytes(TEST_PATH);

        writer.text("cipher".getBytes());
        writer.text("ecdsa".getBytes());

        writer.text("digest".getBytes());
        writer.bytes(TEST_DIGEST);
      }

      CommandAPDU request = apdu(0x00, 0x41, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertSignature(response, TEST_DIGEST, TEST_SEED_DERIVED_PUBLIC_KEY);
    }

    {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 6);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(TEST_MASTER_INDEX);

        writer.text("curve".getBytes());
        writer.text("secp256k1".getBytes());

        writer.text("path".getBytes());
        writer.bytes(TEST_PATH);

        writer.text("cipher".getBytes());
        writer.text("ecdsa".getBytes());

        writer.text("digest".getBytes());
        writer.bytes(TEST_DIGEST);
      }

      CommandAPDU request = apdu(0x00, 0x41, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertSignature(response, TEST_DIGEST, TEST_MASTER_DERIVED_PUBLIC_KEY);
    }

    {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 4);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(TEST_SECP256K1_KEY_INDEX);

        writer.text("cipher".getBytes());
        writer.text("ecdsa".getBytes());

        writer.text("digest".getBytes());
        writer.bytes(TEST_DIGEST);
      }

      CommandAPDU request = apdu(0x00, 0x41, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = connect().transmit(request);

      assertSignature(response, TEST_DIGEST, TEST_SECP256K1_DERIVED_PUBLIC_KEY);
    }
  }

  private void assertSignature(ResponseAPDU response, byte[] digest, byte[] publicKey)
    throws IOException, InterruptedException {
    {
      if (simulator == null) {
        assertNoError(response);

        CBORBufferReader reader = new CBORBufferReader(response.getBytes());
        reader.map();

        byte[] signature = reader.requireKey("signature".getBytes()).bytes();

        System.out.println(String.format("Signature: %s", Hex.toHexString(signature)));

        Assertions.assertEquals(64, signature.length);

        crossVerifySignature(signature, digest, publicKey);
      } else {
        assertError(response, Command.CODE_INTERNAL);
      }
    }
  }

  private void writeAuth(CBORBufferWriter writer, boolean safeAuth) {
    writer.text("auth".getBytes());
    writer.map((short) (safeAuth ? 2 : 1));
    {
      writer.text("pin".getBytes());
      writer.text(safeAuth ? SAFE_PIN : PIN);

      if (safeAuth) {
        writer.text("safe".getBytes());
        writer.bool(true);
      }
    }
  }

  private void assertNoError(ResponseAPDU response) {
    Assertions.assertEquals(0x9000, response.getSW());

    assertNoError(response.getBytes());
  }

  private void assertNoError(byte[] buffer) {
    CBORBufferReader reader = new CBORBufferReader(buffer);
    reader.map();
    byte[] error = reader.key("error".getBytes()) ? reader.text() : null;

    if (error != null) {
      System.out.println(String.format("Error: %s", new String(error)));
    }

    Assertions.assertNull(error);
  }

  private void assertError(ResponseAPDU response, byte[] code) {
    Assertions.assertEquals(0x9000, response.getSW());

    CBORBufferReader reader = new CBORBufferReader(response.getBytes());
    reader.map();
    reader.requireKey("error".getBytes()).map();
    Assertions.assertArrayEquals(code, reader.requireKey("code".getBytes()).text());
  }

  private void crossVerifySignature(byte[] signature, byte[] digest, byte[] publicKey)
    throws IOException, InterruptedException {
    ProcessBuilder pb = new ProcessBuilder(
      "node",
      "scripts/verify-signature.js",
      Hex.toHexString(signature),
      Hex.toHexString(digest),
      Hex.toHexString(publicKey)
    );

    Process process = pb.start();

    Assertions.assertEquals(0, process.waitFor());
  }
}
