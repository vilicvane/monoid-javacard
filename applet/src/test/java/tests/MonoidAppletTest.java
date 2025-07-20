package tests;

import java.util.HashMap;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javacard.framework.AID;

import cz.muni.fi.crocs.rcard.client.CardType;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.utils.AIDUtil;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import monoid.MonoidApplet;
import monoid.MonoidException;
import monoidsafe.MonoidSafeApplet;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@ExtendWith(BailExtension.class)
public class MonoidAppletTest extends AppletTest {
  private static final AID MONOID_SAFE_AID = AIDUtil.create("f16d6f6e6f696400010000");
  private static final AID MONOID_AID = AIDUtil.create("f16d6f6e6f696401010000");

  private static final byte[] SAFE_PIN = "888888".getBytes();
  private static final byte[] PIN = "123456".getBytes();

  private static final byte[] TEST_SEED = Hex.decode(
      "3100314ef25741e991c7bea11a7542b31d873d45a4b6c3da120d8a60553095ddc9a72a1a46e397495402ab9a2fa1190d62d07480275dc91faf12187d46aa0b63");
  private static final byte[] TEST_SEED_INDEX = Hex.decode("01" + "e6e3b7fc12dec011");

  private static final byte[] TEST_MASTER = Hex.decode(
      "5857033b6a5b148e096d2548438cc984b15a5c6590476ae4c12360718ef056c05926524c3889eeccfaaca9805ca83bec6038e01557ca41d11329879b64eb9089");
  private static final byte[] TEST_MASTER_INDEX = Hex.decode("02" + "62420891bc3ff0e9");

  private static final byte[] TEST_KEY = Hex.decode("eff3af6963c58a7a8ad2462bd41486d0a146d8850bd497234da6d419041f4c58");
  private static final byte[] TEST_KEY_INDEX = Hex.decode("03" + "9b3bf69b7418006c");

  private static final byte[] TEST_DIGEST = Hex
      .decode("43ddcab065bcc7bd8d80c479ed29d3658ccf3ac3343b7044013008bde5ca19cf");

  // m/44'/60'/0'/0/0
  private static final byte[] TEST_PATH = Hex.decode("8000002c8000003c800000000000000000000000");

  public MonoidAppletTest() {
    super(
        MONOID_AID,
        System.getenv("CARD_TYPE") != null && System.getenv("CARD_TYPE").equals("physical")
            ? CardType.PHYSICAL
            : CardType.JCARDSIMLOCAL);

    if (simulator != null) {
      simulator.installApplet(MONOID_SAFE_AID, MonoidSafeApplet.class);
      simulator.installApplet(MONOID_AID, MonoidApplet.class);
    }
  }

  @Test
  @Order(1)
  public void hello() throws Exception {
    SimpleCBORWriter cbor = new SimpleCBORWriter();

    cbor.map((short) 0);

    CommandAPDU request = apdu(0x00, 0x20, 0, 0, cbor.getData());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);
  }

  @Test
  @Order(2)
  public void setSafePIN() throws Exception {
    SimpleCBORWriter writer = new SimpleCBORWriter();

    writer.map((short) 2);
    {
      writer.text("pin".getBytes());
      writer.text(SAFE_PIN);

      writer.text("safe".getBytes());
      writer.bool(true);
    }

    CommandAPDU request = apdu(0x00, 0x21, 0, 0, writer.getData());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);
  }

  @Test
  @Order(3)
  public void setPIN() throws Exception {
    SimpleCBORWriter writer = new SimpleCBORWriter();

    writer.map((short) 2);
    {
      writeAuth(writer, true);

      writer.text("pin".getBytes());
      writer.text(PIN);
    }

    CommandAPDU request = apdu(0x00, 0x21, 0, 0, writer.getData());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);

    hello();
  }

  @Test
  @Order(4)
  public void unlockSafe() throws Exception {
    SimpleCBORWriter writer = new SimpleCBORWriter();

    writer.map((short) 3);
    {
      writeAuth(writer, true);

      writer.text("pin".getBytes());
      writer.text(SAFE_PIN);

      writer.text("safe".getBytes());
      writer.bool(true);
    }

    CommandAPDU request = apdu(0x00, 0x21, 0, 0, writer.getData());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);
  }

  @Test
  @Order(5)
  public void list() throws Exception {
    SimpleCBORWriter writer = new SimpleCBORWriter();

    writer.map((short) 1);
    {
      writeAuth(writer, false);
    }

    CommandAPDU request = apdu(0x00, 0x30, 0, 0, writer.getData());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);

    SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());
    reader.map();
    {
      reader.requireKey("items".getBytes()).array();
    }
  }

  @Test
  @Order(6)
  public void createRandomKeys() throws Exception {
    String[] types = { "seed", "master", "key" };

    for (String type : types) {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) (type == "key" ? 3 : 2));
      {
        writeAuth(writer, false);

        writer.text("type".getBytes());
        writer.text(type.getBytes());

        if (type == "key") {
          writer.text("length".getBytes());
          writer.integer((short) 32);
        }
      }

      CommandAPDU request = apdu(0x00, 0x38, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());
      reader.map();
      {
        reader.requireKey("index".getBytes()).bytes();
      }
    }
  }

  @Test
  @Order(7)
  public void setGetClear() throws Exception {
    byte[] index = "someindex".getBytes();
    byte[] data = "some data".getBytes();

    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) 3);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(index);

        writer.text("data".getBytes());
        writer.bytes(data);
      }

      CommandAPDU request = apdu(0x00, 0x32, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);
    }

    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) 2);
      {
        writeAuth(writer, true);

        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x31, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());
      reader.map();
      {
        Assertions.assertArrayEquals(data, reader.requireKey("data".getBytes()).bytes());
      }
    }

    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) 2);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x33, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);
    }

    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) 2);
      {
        writeAuth(writer, true);

        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x31, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertError(response, MonoidException.CODE_NOT_FOUND);
    }
  }

  @Test
  @Order(8)
  public void addTestKeys() throws Exception {
    HashMap<byte[], byte[]> keys = new HashMap<>();

    keys.put(TEST_SEED_INDEX, TEST_SEED);
    keys.put(TEST_MASTER_INDEX, TEST_MASTER);
    keys.put(TEST_KEY_INDEX, TEST_KEY);

    for (HashMap.Entry<byte[], byte[]> entry : keys.entrySet()) {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) 3);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(entry.getKey());

        writer.text("data".getBytes());
        writer.bytes(entry.getValue());
      }

      CommandAPDU request = apdu(0x00, 0x32, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);
    }
  }

  @Test
  @Order(9)
  public void viewKeys() throws Exception {
    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

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

      CommandAPDU request = apdu(0x00, 0x40, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());

      reader.map();
      {
        Assertions.assertArrayEquals(reader.requireKey("publicKey".getBytes()).bytes(),
            Hex.decode("0332066e8d312abcaaf8fea7b2c4f5065410c07b315bde3229f778021b2e763912"));
        Assertions.assertArrayEquals(reader.requireKey("chainCode".getBytes()).bytes(),
            Hex.decode("78307a5fbe683c88809756308869b1e36790820c8a6e6552e1ad848eddbbb8ae"));
      }
    }

    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

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

      CommandAPDU request = apdu(0x00, 0x40, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());

      reader.map();
      {
        Assertions.assertArrayEquals(reader.requireKey("publicKey".getBytes()).bytes(),
            Hex.decode("02541cfc913dc568120034e040063f39933ca6965ac6cbd5e41f5a0c641ace57d3"));
        Assertions.assertArrayEquals(reader.requireKey("chainCode".getBytes()).bytes(),
            Hex.decode("2ff847394908fdc40c3b30c094f07df6ba5bbb1ac5cac1c978b46434ccffacce"));
      }
    }

    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) 3);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(TEST_KEY_INDEX);

        writer.text("curve".getBytes());
        writer.text("secp256k1".getBytes());
      }

      CommandAPDU request = apdu(0x00, 0x40, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());

      reader.map();
      {
        Assertions.assertArrayEquals(reader.requireKey("publicKey".getBytes()).bytes(),
            Hex.decode("031df0b7bb633f1559b9c17d740a8a42d7f6cc3e79e2cefb27093954885e9e13df"));
      }
    }
  }

  @Test
  @Order(10)
  public void sign() throws Exception {
    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

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

      CommandAPDU request = apdu(0x00, 0x41, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());

      reader.map();
      {
        reader.requireKey("signature".getBytes()).bytes();
      }
    }

    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

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

      CommandAPDU request = apdu(0x00, 0x41, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());

      reader.map();
      {
        reader.requireKey("signature".getBytes()).bytes();
      }
    }

    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) 5);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(TEST_KEY_INDEX);

        writer.text("curve".getBytes());
        writer.text("secp256k1".getBytes());

        writer.text("cipher".getBytes());
        writer.text("ecdsa".getBytes());

        writer.text("digest".getBytes());
        writer.bytes(TEST_DIGEST);
      }

      CommandAPDU request = apdu(0x00, 0x41, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());

      reader.map();
      {
        reader.requireKey("signature".getBytes()).bytes();
      }
    }
  }

  private void writeAuth(SimpleCBORWriter writer, boolean safeAuth) {
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

    SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());
    reader.map();
    Assertions.assertFalse(reader.key("error".getBytes()));
  }

  private void assertError(ResponseAPDU response, byte[] code) {
    Assertions.assertEquals(0x9000, response.getSW());

    SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());
    reader.map();
    reader.requireKey("error".getBytes()).map();
    Assertions.assertArrayEquals(code, reader.requireKey("code".getBytes()).text());
  }
}
