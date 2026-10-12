package tests;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.utils.AIDUtil;
import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoid.CBORBufferReader;
import monoid.CBORBufferWriter;
import monoid.Command;
import monoid.MonoidApplet;
import monoid.MonoidException;
import monoid.Safe;
import monoid.SafeException;
import monoidsafe.MonoidSafeApplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
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
      System.setProperty("com.licel.jcardsim.bouncycastle.rsa.allow_unsafe_mod", "true");

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
    assertFeatures(response);

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
    assertFeatures(response);

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

    CommandAPDU request = apdu(0x00, 0x22, 0, 0, writer.getDataBuffer());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(4)
  public void listWithWrongPIN() throws Exception {
    CBORBufferWriter writer = new CBORBufferWriter();

    writer.map((short) 1);
    {
      writer.text("pin".getBytes());
      writer.text(PIN);
    }

    CommandAPDU request = apdu(0x00, 0x21, 0, 0, writer.getDataBuffer());

    ResponseAPDU response = connect().transmit(request);

    assertError(response, MonoidException.CODE_INVALID_PIN);
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(5)
  public void setPIN() throws Exception {
    CardManager manager = connect();

    authenticate(manager, true);

    CBORBufferWriter writer = new CBORBufferWriter();

    writer.map((short) 1);
    {
      writer.text("pin".getBytes());
      writer.text(PIN);
    }

    CommandAPDU request = apdu(0x00, 0x22, 0, 0, writer.getDataBuffer());

    ResponseAPDU response = manager.transmit(request);

    assertNoError(response);
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(6)
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
  @Order(7)
  public void unlockSafe() throws Exception {
    CardManager manager = connect();

    authenticate(manager, true);

    CBORBufferWriter writer = new CBORBufferWriter();

    writer.map((short) 2);
    {
      writer.text("pin".getBytes());
      writer.text(SAFE_PIN);

      writer.text("safe".getBytes());
      writer.bool(true);
    }

    CommandAPDU request = apdu(0x00, 0x22, 0, 0, writer.getDataBuffer());

    ResponseAPDU response = manager.transmit(request);

    assertNoError(response);
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(8)
  public void createRandomKeys() throws Exception {
    CardManager manager = connect();

    authenticate(manager, false);

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

      writer.map((short) (length == 0 ? 1 : 2));
      {
        writer.text("type".getBytes());
        writer.text(type);

        if (length > 0) {
          writer.text("length".getBytes());
          writer.integer(length);
        }
      }

      CommandAPDU request = apdu(0x00, 0x38, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

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
  @Order(9)
  public void createSetViewGetRemove() throws Exception {
    byte[] index = "some index".getBytes(); // "coincidentally" 10 bytes
    byte[] alias = "some alias".getBytes();
    byte[] data = "some data".getBytes();

    {
      // create

      CardManager manager = connect();

      authenticate(manager, false);

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 2);
      {
        writer.text("index".getBytes());
        writer.bytes(index);

        writer.text("data".getBytes());
        writer.bytes(data);
      }

      CommandAPDU request = apdu(0x00, 0x34, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

      assertNoError(response);

      CBORBufferReader reader = new CBORBufferReader(response.getBytes());
      reader.map();
      {
        Assertions.assertArrayEquals(index, reader.requireKey("index".getBytes()).bytes());
      }
    }

    {
      // set

      CardManager manager = connect();

      authenticate(manager, false);

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 2);
      {
        writer.text("index".getBytes());
        writer.bytes(index);

        writer.text("alias".getBytes());
        writer.text(alias);
      }

      CommandAPDU request = apdu(0x00, 0x33, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

      assertNoError(response);
    }

    {
      // view

      CardManager manager = connect();

      authenticate(manager, false);

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 1);
      {
        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x31, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

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

      CardManager manager = connect();

      authenticate(manager, true);

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 1);
      {
        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x32, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

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

      CardManager manager = connect();

      authenticate(manager, false);

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 1);
      {
        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x35, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

      assertNoError(response);
    }

    {
      // get

      CardManager manager = connect();

      authenticate(manager, true);

      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 1);
      {
        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x32, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

      assertError(response, SafeException.CODE_NOT_FOUND);
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(10)
  public void addTestKeys() throws Exception {
    HashMap<byte[], byte[]> keys = new HashMap<>();

    keys.put(TEST_SEED_INDEX, TEST_SEED);
    keys.put(TEST_MASTER_INDEX, TEST_MASTER);
    keys.put(TEST_SECP256K1_KEY_INDEX, TEST_SECP256K1_KEY);

    CardManager manager = connect();

    authenticate(manager, false);

    for (HashMap.Entry<byte[], byte[]> entry : keys.entrySet()) {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 2);
      {
        writer.text("index".getBytes());
        writer.bytes(entry.getKey());

        writer.text("data".getBytes());
        writer.bytes(entry.getValue());
      }

      CommandAPDU request = apdu(0x00, 0x34, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

      assertNoError(response);
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(11)
  public void list() throws Exception {
    CardManager manager = connect();

    authenticate(manager, false);

    CBORBufferWriter writer = new CBORBufferWriter();

    writer.map((short) 0);

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
  @Order(12)
  public void viewKeys() throws Exception {
    CardManager manager = connect();

    authenticate(manager, false);

    {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 4);
      {
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

      ResponseAPDU response = manager.transmit(request);

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

      writer.map((short) 3);
      {
        writer.text("index".getBytes());
        writer.bytes(TEST_MASTER_INDEX);

        writer.text("curve".getBytes());
        writer.text("secp256k1".getBytes());

        writer.text("path".getBytes());
        writer.bytes(TEST_PATH);
      }

      CommandAPDU request = apdu(0x00, 0x40, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

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

      writer.map((short) 2);
      {
        writer.text("index".getBytes());
        writer.bytes(TEST_SECP256K1_KEY_INDEX);

        writer.text("curve".getBytes());
        writer.text("secp256k1".getBytes());
      }

      CommandAPDU request = apdu(0x00, 0x40, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

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
  @Order(13)
  public void sign() throws Exception {
    CardManager manager = connect();

    authenticate(manager, false);

    {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 6);
      {
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

      ResponseAPDU response = manager.transmit(request);

      assertSignature(response, TEST_DIGEST, TEST_SEED_DERIVED_PUBLIC_KEY);
    }

    {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 5);
      {
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

      ResponseAPDU response = manager.transmit(request);

      assertSignature(response, TEST_DIGEST, TEST_MASTER_DERIVED_PUBLIC_KEY);
    }

    {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 3);
      {
        writer.text("index".getBytes());
        writer.bytes(TEST_SECP256K1_KEY_INDEX);

        writer.text("cipher".getBytes());
        writer.text("ecdsa".getBytes());

        writer.text("digest".getBytes());
        writer.bytes(TEST_DIGEST);
      }

      CommandAPDU request = apdu(0x00, 0x41, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

      assertSignature(response, TEST_DIGEST, TEST_SECP256K1_DERIVED_PUBLIC_KEY);
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(14)
  public void signEDDSAMessage() throws Exception {
    byte[][] indices = { TEST_SEED_INDEX, TEST_MASTER_INDEX };
    // Node.js crypto HMAC-SHA512 derivation and Ed25519 signing of 0x72 at m/44'/501'/0'/0'.
    byte[][] signatures = {
      Hex.decode(
        "fcc50cf4592b2336b2c7c0915b2102656ee067f3fbff8b5454863cef0cf037a687945e97290a707faf9e20685d2ad9a12c89e8a4c4a59f791ea13644d160990e"
      ),
      Hex.decode(
        "46bd2dd36ded172a640133204aea836f776662dc9ad597393419979bae920a42b626f8efec906a4d4cc238c94350071a4a900298472a096cfa2340cb5ecb5f03"
      ),
    };

    CardManager manager = connect();

    authenticate(manager, false);

    for (int index = 0; index < indices.length; index++) {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 6);
      {
        writer.text("index".getBytes());
        writer.bytes(indices[index]);

        writer.text("curve".getBytes());
        writer.text("ed25519".getBytes());

        writer.text("seed".getBytes());
        writer.text("ed25519 seed".getBytes());

        writer.text("path".getBytes());
        writer.bytes(Hex.decode("8000002c800001f58000000080000000"));

        writer.text("cipher".getBytes());
        writer.text("eddsa".getBytes());

        writer.text("message".getBytes());
        writer.bytes(Hex.decode("72"));
      }

      CommandAPDU request = apdu(0x00, 0x41, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

      assertNoError(response);

      CBORBufferReader reader = new CBORBufferReader(response.getBytes());
      reader.map();
      Assertions.assertArrayEquals(
        signatures[index],
        reader.requireKey("signature".getBytes()).bytes()
      );
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(15)
  public void viewEdwardsKeys() throws Exception {
    byte[][] indices = { TEST_SEED_INDEX, TEST_MASTER_INDEX };
    // Node.js crypto HMAC-SHA512 derivation and Ed25519 public keys at m/44'/501'/0'/0'.
    byte[][] publicKeys = {
      Hex.decode("002dc5ffc81291faa8f95528b8366a3c22671ea7ef34df78a7e114f5fb86c67a"),
      Hex.decode("7bf87e36e6c74f6e1867d6185b4bada35a2a2b6dde341f108a1354573d787682"),
    };
    byte[][] chainCodes = {
      Hex.decode("a9222e023e472495cc6e674d480b5751e597c681ae819de014f6c781746a5c58"),
      Hex.decode("1ae04e54c925c17a4a321906bae967dd1ec31d0aad405bcd858dd979e17a0e2a"),
    };

    CardManager manager = connect();

    authenticate(manager, false);

    for (int index = 0; index < indices.length; index++) {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 4);
      {
        writer.text("index".getBytes());
        writer.bytes(indices[index]);

        writer.text("curve".getBytes());
        writer.text("ed25519".getBytes());

        writer.text("seed".getBytes());
        writer.text("ed25519 seed".getBytes());

        writer.text("path".getBytes());
        writer.bytes(Hex.decode("8000002c800001f58000000080000000"));
      }

      CommandAPDU request = apdu(0x00, 0x40, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

      assertNoError(response);

      CBORBufferReader reader = new CBORBufferReader(response.getBytes());
      Assertions.assertEquals(2, reader.map());
      Assertions.assertArrayEquals(
        publicKeys[index],
        reader.requireKey("publicKey".getBytes()).bytes()
      );
      Assertions.assertArrayEquals(
        chainCodes[index],
        reader.requireKey("chainCode".getBytes()).bytes()
      );
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(16)
  public void fragmentedRequests() throws Exception {
    CardManager manager = connect();
    byte[] request = paddedHello(513);

    assertAcknowledgement(transmitFrame(manager, 0x90, 0x20, 0, 0, new byte[] { request[0] }));
    assertInvalidResponseHeaders(manager);
    Assertions.assertEquals(0x6883, transmitFrame(manager, 0, 0xC0, 0, 0, new byte[0]).getSW());
    assertAcknowledgement(
      transmitFrame(manager, 0xB0, 0x20, 0, 0, Arrays.copyOfRange(request, 1, 256))
    );
    assertAcknowledgement(
      transmitFrame(manager, 0xB0, 0x20, 0, 0, Arrays.copyOfRange(request, 256, 511))
    );
    ResponseAPDU response = transmitFrame(
      manager,
      0xA0,
      0x20,
      0,
      0,
      Arrays.copyOfRange(request, 511, request.length)
    );

    assertNoError(response);
    assertFeatures(response);

    for (int chunkLength : new int[] { 15, 16, 17, 255 }) {
      response = transmitFragments(manager, 0x20, request, chunkLength);
      assertNoError(response);
      assertFeatures(response);
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(17)
  public void replacementRequests() throws Exception {
    CardManager manager = connect();

    assertAcknowledgement(transmitFrame(manager, 0x90, 0x20, 0, 0, new byte[] { (byte) 0xFF }));
    ResponseAPDU response = transmitFragments(manager, 0x20, paddedHello(300), 255);
    assertNoError(response);
    assertFeatures(response);

    assertAcknowledgement(transmitFrame(manager, 0x90, 0x20, 0, 0, new byte[] { (byte) 0xFF }));
    response = transmitFrame(manager, 0, 0x20, 0, 0, new byte[] { (byte) 0xA0 });
    assertNoError(response);
    assertFeatures(response);
    Assertions.assertEquals(
      0x6883,
      transmitFrame(manager, 0xA0, 0x20, 0, 0, new byte[] { 0 }).getSW()
    );
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(18)
  public void invalidRequestFragments() throws Exception {
    CardManager manager = connect();
    // CLA, INS, P1, P2, data length, expected status.
    int[][] invalidFrames = {
      { 0x80, 0x20, 0, 0, 1, 0x6E00 },
      { 0x00, 0x7F, 0, 0, 1, 0x6D00 },
      { 0xB0, 0x2F, 0, 0, 1, 0x6883 },
      { 0xB0, 0x20, 1, 0, 1, 0x6883 },
      { 0xA0, 0x20, 0, 1, 1, 0x6883 },
      { 0xB0, 0x20, 0, 0, 0, 0x6700 },
      { 0xA0, 0x20, 0, 0, 0, 0x6700 },
      { 0x00, 0x20, 0, 0, 0, 0x6700 },
      { 0x90, 0x20, 0, 0, 0, 0x6700 },
    };

    for (int[] frame : invalidFrames) {
      assertAcknowledgement(transmitFrame(manager, 0x90, 0x20, 0, 0, new byte[] { (byte) 0xA1 }));
      Assertions.assertEquals(
        frame[5],
        transmitFrame(manager, frame[0], frame[1], frame[2], frame[3], new byte[frame[4]]).getSW()
      );

      for (int cla : new int[] { 0xB0, 0xA0 }) {
        Assertions.assertEquals(
          0x6883,
          transmitFrame(manager, cla, 0x20, 0, 0, new byte[] { 0 }).getSW()
        );
      }

      assertNoError(transmitFrame(manager, 0, 0x20, 0, 0, new byte[] { (byte) 0xA0 }));
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(19)
  public void requestLengthLimit() throws Exception {
    CardManager manager = connect();

    ResponseAPDU response = transmitFragments(manager, 0x20, paddedHello(8192), 255);
    assertNoError(response);
    assertFeatures(response);

    Assertions.assertEquals(
      0x6700,
      transmitFragments(manager, 0x20, paddedHello(8193), 255).getSW()
    );
    Assertions.assertEquals(
      0x6883,
      transmitFrame(manager, 0xA0, 0x20, 0, 0, new byte[] { 0 }).getSW()
    );
    assertNoError(transmitFragments(manager, 0x20, paddedHello(300), 255));
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(20)
  public void signFragmentedEDDSAMessage() throws Exception {
    CardManager manager = connect();

    authenticate(manager, false);

    int[] messageLengths = { 512, 1167, 4032, 8096, 8114 };
    byte[][] indices = {
      TEST_SEED_INDEX,
      TEST_SEED_INDEX,
      TEST_SEED_INDEX,
      TEST_SEED_INDEX,
      TEST_MASTER_INDEX,
    };
    // Node.js crypto HMAC-SHA512 derivation and Ed25519 signing of repeated bytes 0..255.
    byte[][] signatures = {
      Hex.decode(
        "487e3d6fdfdb499671f05f091e092940b90a848ff115695ef3920d8fa2c0df5a577c547115a04a8bae5ac2fc504db8dd980b8958b19404115edc60579b66570b"
      ),
      Hex.decode(
        "67be39bc0d4ab53389fd2d905f2169512622d5b8ebfa3e39b26c7c9bb21cf94285874c9f1f43cefecd7db94ae995f73b8a3207a0f17bd3414c6861f2a86fbe00"
      ),
      Hex.decode(
        "2ec71809c29e321a614eae5db09aba73d8695a2104e8b8ea75ecef82a25a0ed32fcca5eb8cd004251b13e0600eb90fb5cb2fcdc35df3799dd4329b35cae1340c"
      ),
      Hex.decode(
        "69ab80854ccec3e35bc85fd04833bd4361e9c3bd85eefd4473a2ce63265bb7bb06a2b72f32d476fb88b8e3934b40a74c10ee9c5694e241b281595050f8267f06"
      ),
      Hex.decode(
        "6cf08b971f6342ebbe331f2fecf832ba3987667039fe2336f37ad996e2d400f75dbc57eab0a38b49e072849f95039fa6cb854afbbc637ebe1fca329ae3502e02"
      ),
    };

    for (int index = 0; index < messageLengths.length; index++) {
      boolean seed = indices[index] == TEST_SEED_INDEX;
      byte[] message = new byte[messageLengths[index]];

      for (int offset = 0; offset < message.length; offset++) {
        message[offset] = (byte) offset;
      }

      for (boolean messageFirst : new boolean[] { false, true }) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map((short) (seed ? 6 : 5));
        {
          if (messageFirst) {
            writer.text("message".getBytes());
            writer.bytes(message);
          }

          writer.text("index".getBytes());
          writer.bytes(indices[index]);
          writer.text("curve".getBytes());
          writer.text("ed25519".getBytes());

          if (seed) {
            writer.text("seed".getBytes());
            writer.text("ed25519 seed".getBytes());
          }

          writer.text("path".getBytes());
          writer.bytes(Hex.decode("8000002c800001f58000000080000000"));
          writer.text("cipher".getBytes());
          writer.text("eddsa".getBytes());

          if (!messageFirst) {
            writer.text("message".getBytes());
            writer.bytes(message);
          }
        }

        byte[] request = writer.getDataBuffer();

        if (message.length >= 8096) {
          Assertions.assertEquals(8192, request.length);
        }

        ResponseAPDU response = transmitFragments(manager, 0x41, request, 255);
        assertNoError(response);

        CBORBufferReader reader = new CBORBufferReader(response.getBytes());
        Assertions.assertEquals(1, reader.map());
        Assertions.assertArrayEquals(
          signatures[index],
          reader.requireKey("signature".getBytes()).bytes()
        );
      }
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(21)
  public void selectionAndResetCancelRequest() throws Exception {
    Assumptions.assumeTrue(simulator != null);

    CardManager manager = connect();

    for (int operation = 0; operation < 3; operation++) {
      assertAcknowledgement(transmitFrame(manager, 0x90, 0x20, 0, 0, new byte[] { (byte) 0xA1 }));

      if (operation == 1) {
        Assertions.assertTrue(simulator.selectApplet(MONOID_SAFE_AID));
      } else if (operation == 2) {
        simulator.reset();
      }

      Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
      Assertions.assertEquals(
        0x6883,
        transmitFrame(manager, 0xA0, 0x20, 0, 0, new byte[] { 0 }).getSW()
      );
      assertNoError(transmitFragments(manager, 0x20, paddedHello(300), 255));
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(22)
  public void fragmentedRequestAndResponse() throws Exception {
    CardManager manager = connect();

    authenticate(manager, false);

    ResponseAPDU first = transmitFragments(manager, 0x30, paddedHello(300), 255);
    Assertions.assertEquals(0x6100, first.getSW() & 0xFF00);
    Assertions.assertEquals(256, first.getData().length);
    assertInvalidResponseHeaders(manager);

    ResponseAPDU last = transmitFrame(manager, 0, 0xC0, 0, 0, new byte[0]);
    Assertions.assertEquals(0x9000, last.getSW());

    byte[] response = Arrays.copyOf(
      first.getData(),
      first.getData().length + last.getData().length
    );
    System.arraycopy(last.getData(), 0, response, first.getData().length, last.getData().length);
    assertNoError(response);

    CBORBufferReader reader = new CBORBufferReader(response);
    reader.map();
    Assertions.assertEquals(9, reader.requireKey("items".getBytes()).array());
    Assertions.assertTrue(reader.index((short) 8));
    reader.map();
    Assertions.assertEquals(10, reader.requireKey("index".getBytes()).bytes().length);
    Assertions.assertEquals(0x6985, transmitFrame(manager, 0, 0xC0, 0, 0, new byte[0]).getSW());
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(23)
  public void newRequestCancelsResponse() throws Exception {
    CardManager manager = connect();

    authenticate(manager, false);

    for (boolean fragmented : new boolean[] { false, true }) {
      ResponseAPDU response = transmitFragments(manager, 0x30, paddedHello(300), 255);
      Assertions.assertEquals(0x6100, response.getSW() & 0xFF00);

      if (fragmented) {
        assertAcknowledgement(transmitFrame(manager, 0x90, 0x20, 0, 0, new byte[] { (byte) 0xA1 }));
        Assertions.assertEquals(0x6883, transmitFrame(manager, 0, 0xC0, 0, 0, new byte[0]).getSW());
        response = transmitFrame(manager, 0xA0, 0x20, 0, 0, Hex.decode("6000"));
      } else {
        response = transmitFrame(manager, 0, 0x20, 0, 0, new byte[] { (byte) 0xA0 });
      }

      assertNoError(response);
      assertFeatures(response);
      Assertions.assertEquals(0x6985, transmitFrame(manager, 0, 0xC0, 0, 0, new byte[0]).getSW());
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(24)
  public void fragmentedDataRoundTrip() throws Exception {
    CardManager manager = connect();

    authenticate(manager, true);

    byte[] index = "fragmented".getBytes();
    byte[] data = new byte[600];

    for (int offset = 0; offset < data.length; offset++) {
      data[offset] = (byte) (offset ^ 0xA5);
    }

    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    {
      writer.text("index".getBytes());
      writer.bytes(index);

      writer.text("data".getBytes());
      writer.bytes(data);
    }

    ResponseAPDU response = transmitFragments(manager, 0x34, writer.getDataBuffer(), 255);
    assertNoError(response);

    writer.reset();
    writer.map((short) 1);
    writer.text("index".getBytes());
    writer.bytes(index);
    byte[] request = writer.getDataBuffer();

    try {
      response = transmitFragments(manager, 0x32, request, 7);
      ByteArrayOutputStream responseData = new ByteArrayOutputStream();
      int chunks = 0;

      while (true) {
        responseData.write(response.getData());
        chunks++;

        if (response.getSW() == 0x9000) {
          break;
        }

        Assertions.assertEquals(0x6100, response.getSW() & 0xFF00);
        Assertions.assertEquals(256, response.getData().length);
        response = transmitFrame(manager, 0, 0xC0, 0, 0, new byte[0]);
      }

      Assertions.assertEquals(3, chunks);
      assertNoError(responseData.toByteArray());

      CBORBufferReader reader = new CBORBufferReader(responseData.toByteArray());
      reader.map();
      Assertions.assertArrayEquals(data, reader.requireKey("data".getBytes()).bytes());
      Assertions.assertEquals(0x6985, transmitFrame(manager, 0, 0xC0, 0, 0, new byte[0]).getSW());
    } finally {
      assertNoError(transmitFrame(manager, 0, 0x35, 0, 0, request));
    }
  }

  private void assertInvalidResponseHeaders(CardManager manager)
    throws javax.smartcardio.CardException {
    int[][] headers = { { 0x90, 0, 0, 0x6E00 }, { 0x00, 1, 0, 0x6A86 }, { 0x00, 0, 1, 0x6A86 } };

    for (int[] header : headers) {
      Assertions.assertEquals(
        header[3],
        transmitFrame(manager, header[0], 0xC0, header[1], header[2], new byte[0]).getSW()
      );
    }
  }

  private byte[] paddedHello(int length) {
    byte[] request = new byte[length];
    request[0] = (byte) 0xA1;
    request[1] = 0x67;
    System.arraycopy("padding".getBytes(), 0, request, 2, 7);
    request[9] = 0x59;
    request[10] = (byte) ((length - 12) >> 8);
    request[11] = (byte) (length - 12);
    return request;
  }

  private ResponseAPDU transmitFragments(CardManager manager, int ins, byte[] request, int length)
    throws javax.smartcardio.CardException {
    for (int offset = 0; offset < request.length; offset += length) {
      int end = Math.min(offset + length, request.length);
      boolean last = end == request.length;
      int cla = offset == 0 ? (last ? 0x00 : 0x90) : (last ? 0xA0 : 0xB0);
      ResponseAPDU response = transmitFrame(
        manager,
        cla,
        ins,
        0,
        0,
        Arrays.copyOfRange(request, offset, end)
      );

      if (last) {
        return response;
      }

      assertAcknowledgement(response);
    }

    throw new IllegalArgumentException("Empty request");
  }

  private ResponseAPDU transmitFrame(
    CardManager manager,
    int cla,
    int ins,
    int p1,
    int p2,
    byte[] data
  ) throws javax.smartcardio.CardException {
    CommandAPDU request = apdu(cla, ins, p1, p2, data);
    return simulator == null
      ? manager.getChannel().transmit(request)
      : simulator.transmitCommand(request);
  }

  private void assertAcknowledgement(ResponseAPDU response) {
    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertEquals(0, response.getData().length);
  }

  private void assertFeatures(ResponseAPDU response) {
    String[] curves = { "secp256k1", "ed25519" };
    String[] ciphers = { "ecdsa", "eddsa" };

    for (short index = 0; index < curves.length; index++) {
      CBORBufferReader reader = new CBORBufferReader(response.getBytes());
      reader.map();
      Assertions.assertEquals(1, reader.requireKey("features".getBytes()).map());
      Assertions.assertEquals(2, reader.requireKey("curves".getBytes()).array());
      reader.index(index);
      Assertions.assertEquals(2, reader.map());
      Assertions.assertArrayEquals(
        curves[index].getBytes(),
        reader.requireKey("name".getBytes()).text()
      );
      Assertions.assertEquals(1, reader.requireKey("ciphers".getBytes()).array());
      reader.index((short) 0);
      Assertions.assertArrayEquals(ciphers[index].getBytes(), reader.text());
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

  private void authenticate(CardManager manager, boolean safeAuth)
    throws javax.smartcardio.CardException {
    CBORBufferWriter writer = new CBORBufferWriter();

    writer.map((short) (safeAuth ? 2 : 1));
    {
      writer.text("pin".getBytes());
      writer.text(safeAuth ? SAFE_PIN : PIN);

      if (safeAuth) {
        writer.text("safe".getBytes());
        writer.bool(true);
      }
    }

    CommandAPDU request = apdu(0x00, 0x21, 0, 0, writer.getDataBuffer());

    ResponseAPDU response = manager.transmit(request);

    assertNoError(response);
  }

  private void assertNoError(ResponseAPDU response) {
    Assertions.assertEquals(0x9000, response.getSW());

    assertNoError(response.getBytes());
  }

  private void assertNoError(byte[] buffer) {
    CBORBufferReader reader = new CBORBufferReader(buffer);
    reader.map();
    if (!reader.key("error".getBytes())) {
      return;
    }

    reader.map();

    byte[] code = reader.requireKey("code".getBytes()).text();

    System.out.println(String.format("Error: %s", new String(code)));

    Assertions.assertNull(code);
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
