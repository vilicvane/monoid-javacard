package tests;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.bouncycastle.crypto.params.ECDomainParameters;
import com.licel.jcardsim.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.licel.jcardsim.bouncycastle.crypto.signers.ECDSASigner;
import com.licel.jcardsim.bouncycastle.util.BigIntegers;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.utils.AIDUtil;
import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoid.MonoidApplet;
import monoid.MonoidException;
import monoid.Safe;
import monoid.SafeException;
import monoididentity.MonoidIdentityApplet;
import monoidlib.CBORBufferReader;
import monoidlib.CBORBufferWriter;
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

  private static final AID MONOID_IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_IDENTITY_AID}}"
    "f06d6f6e6f69640001"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );

  private static final byte[] SECRET_PIN = "888888".getBytes();
  private static final byte[] PIN = "123456".getBytes();

  private static final byte[] TEST_SEED = Hex.decode(
    "3100314ef25741e991c7bea11a7542b31d873d45a4b6c3da120d8a60553095ddc9a72a1a46e397495402ab9a2fa1190d62d07480275dc91faf12187d46aa0b63"
  );
  private static final byte[] TEST_SEED_INDEX = Hex.decode("0240" + "7e083e348d6eb20e");

  private static final byte[] TEST_SECP256K1_KEY = Hex.decode(
    "eff3af6963c58a7a8ad2462bd41486d0a146d8850bd497234da6d419041f4c58"
  );
  private static final byte[] TEST_SECP256K1_KEY_INDEX = Hex.decode("0301" + "b5519fdc940daeb3");

  // RFC 8032, section 7.1, test 2; this is a public example private key seed.
  private static final byte[] TEST_ED25519_KEY = Hex.decode(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
  );
  private static final byte[] TEST_ED25519_KEY_INDEX = Hex.decode("0401" + "3d2d9682cdba5296");

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

  private static final byte[] TEST_SECP256K1_DERIVED_PUBLIC_KEY = Hex.decode(
    "031df0b7bb633f1559b9c17d740a8a42d7f6cc3e79e2cefb27093954885e9e13df"
  );

  private static final byte[] TEST_ED25519_PUBLIC_KEY = Hex.decode(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
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

      simulator.installApplet(MONOID_IDENTITY_AID, MonoidIdentityApplet.class);
      simulator.installApplet(MONOID_AID, MonoidApplet.class);
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(1)
  public void firstHello() throws Exception {
    CardManager manager = connect();
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 0);

    CommandAPDU request = apdu(0x00, 0x20, 0, 0, writer.getDataBuffer());
    ResponseAPDU response = manager.transmit(request);

    assertNoError(response);
    assertHello(response, false);
    Assertions.assertArrayEquals(response.getData(), manager.transmit(request).getData());
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
      writer.text(SECRET_PIN);

      writer.text("secret".getBytes());
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

    assertHello(response, true);
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(7)
  public void updateSafePIN() throws Exception {
    CardManager manager = connect();

    authenticate(manager, true);

    CBORBufferWriter writer = new CBORBufferWriter();

    writer.map((short) 2);
    {
      writer.text("pin".getBytes());
      writer.text(SECRET_PIN);

      writer.text("secret".getBytes());
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
      Safe.TYPE_TEXT_SECP256K1,
    };

    short[] lengths = { 32, 48, 64, 128, 0 };

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
        Assertions.assertFalse(reader.requireKey("secret".getBytes()).bool());
        Assertions.assertFalse(reader.key("data".getBytes()));
      }
    }

    {
      // get

      CardManager manager = connect();

      authenticate(manager, false);

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
      Assertions.assertEquals(1, reader.map());
      {
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
    keys.put(TEST_SECP256K1_KEY_INDEX, TEST_SECP256K1_KEY);
    keys.put(TEST_ED25519_KEY_INDEX, TEST_ED25519_KEY);

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
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      ResponseAPDU response = manager.transmit(apdu(0x00, 0x30, 0, 0, writer.getDataBuffer()));

      while (true) {
        output.write(response.getData());

        if (response.getSW1() != 0x61) {
          break;
        }

        response = manager.transmit(
          new CommandAPDU(0x00, 0xC0, 0, 0, response.getSW2() == 0 ? 256 : response.getSW2())
        );
      }

      Assertions.assertEquals(0x9000, response.getSW());
      buffer = output.toByteArray();
      assertNoError(buffer);
    }

    CBORBufferReader reader = new CBORBufferReader(buffer);
    reader.map();
    {
      Assertions.assertEquals(8, reader.requireKey("items".getBytes()).array());

      Assertions.assertTrue(reader.index((short) 7));
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

      writer.map((short) 3);
      {
        writer.text("index".getBytes());
        writer.bytes(TEST_SEED_INDEX);

        writer.text("type".getBytes());
        writer.text("seed".getBytes());

        writeDerivation(writer, false, TEST_PATH);
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

      writer.map((short) 2);
      {
        writer.text("index".getBytes());
        writer.bytes(TEST_SECP256K1_KEY_INDEX);

        writer.text("type".getBytes());
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

    {
      CBORBufferWriter writer = new CBORBufferWriter();

      writer.map((short) 2);
      {
        writer.text("index".getBytes());
        writer.bytes(TEST_ED25519_KEY_INDEX);

        writer.text("type".getBytes());
        writer.text("ed25519".getBytes());
      }

      CommandAPDU request = apdu(0x00, 0x40, 0, 0, writer.getDataBuffer());

      ResponseAPDU response = manager.transmit(request);

      assertNoError(response);

      CBORBufferReader reader = new CBORBufferReader(response.getBytes());

      Assertions.assertEquals(1, reader.map());
      Assertions.assertArrayEquals(
        TEST_ED25519_PUBLIC_KEY,
        reader.requireKey("publicKey".getBytes()).bytes()
      );
      Assertions.assertFalse(reader.key("chainCode".getBytes()));
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

      writer.map((short) 5);
      {
        writer.text("index".getBytes());
        writer.bytes(TEST_SEED_INDEX);

        writer.text("type".getBytes());
        writer.text("seed".getBytes());

        writeDerivation(writer, false, TEST_PATH);

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

      writer.map((short) 4);
      {
        writer.text("index".getBytes());
        writer.bytes(TEST_SECP256K1_KEY_INDEX);

        writer.text("type".getBytes());
        writer.text("secp256k1".getBytes());

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
  public void signED25519Message() throws Exception {
    // Node.js crypto HMAC-SHA512 derivation and Ed25519 signing of 0x72 at m/44'/501'/0'/0'.
    byte[] signature = Hex.decode(
      "fcc50cf4592b2336b2c7c0915b2102656ee067f3fbff8b5454863cef0cf037a687945e97290a707faf9e20685d2ad9a12c89e8a4c4a59f791ea13644d160990e"
    );

    CardManager manager = connect();

    authenticate(manager, false);

    CBORBufferWriter writer = new CBORBufferWriter();

    writer.map((short) 5);
    {
      writer.text("index".getBytes());
      writer.bytes(TEST_SEED_INDEX);

      writer.text("type".getBytes());
      writer.text("seed".getBytes());

      writeDerivation(writer, true, Hex.decode("8000002c800001f58000000080000000"));

      writer.text("cipher".getBytes());
      writer.text("ed25519".getBytes());

      writer.text("message".getBytes());
      writer.bytes(Hex.decode("72"));
    }

    CommandAPDU request = apdu(0x00, 0x41, 0, 0, writer.getDataBuffer());

    ResponseAPDU response = manager.transmit(request);

    assertNoError(response);

    CBORBufferReader reader = new CBORBufferReader(response.getBytes());
    reader.map();
    Assertions.assertArrayEquals(signature, reader.requireKey("signature".getBytes()).bytes());
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(15)
  public void viewEdwardsKeys() throws Exception {
    // Node.js crypto HMAC-SHA512 derivation and Ed25519 public keys at m/44'/501'/0'/0'.
    byte[] publicKey = Hex.decode(
      "002dc5ffc81291faa8f95528b8366a3c22671ea7ef34df78a7e114f5fb86c67a"
    );
    byte[] chainCode = Hex.decode(
      "a9222e023e472495cc6e674d480b5751e597c681ae819de014f6c781746a5c58"
    );

    CardManager manager = connect();

    authenticate(manager, false);

    CBORBufferWriter writer = new CBORBufferWriter();

    writer.map((short) 3);
    {
      writer.text("index".getBytes());
      writer.bytes(TEST_SEED_INDEX);

      writer.text("type".getBytes());
      writer.text("seed".getBytes());

      writeDerivation(writer, true, Hex.decode("8000002c800001f58000000080000000"));
    }

    CommandAPDU request = apdu(0x00, 0x40, 0, 0, writer.getDataBuffer());

    ResponseAPDU response = manager.transmit(request);

    assertNoError(response);

    CBORBufferReader reader = new CBORBufferReader(response.getBytes());
    Assertions.assertEquals(2, reader.map());
    Assertions.assertArrayEquals(publicKey, reader.requireKey("publicKey".getBytes()).bytes());
    Assertions.assertArrayEquals(chainCode, reader.requireKey("chainCode".getBytes()).bytes());
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
    assertHello(response, true);

    for (int chunkLength : new int[] { 15, 16, 17, 255 }) {
      response = transmitFragments(manager, 0x20, request, chunkLength);
      assertNoError(response);
      assertHello(response, true);
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
    assertHello(response, true);

    assertAcknowledgement(transmitFrame(manager, 0x90, 0x20, 0, 0, new byte[] { (byte) 0xFF }));
    response = transmitFrame(manager, 0, 0x20, 0, 0, new byte[] { (byte) 0xA0 });
    assertNoError(response);
    assertHello(response, true);
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
    assertHello(response, true);

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
  public void signFragmentedED25519Message() throws Exception {
    CardManager manager = connect();

    authenticate(manager, false);

    int[] messageLengths = { 512, 1167, 4032, 8078 };
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
        "20e1b5301e69803696619d31eefc06a4651ecec9ea773882676cb370f89461117a34fa79b00e3f4abc08b5520df5b02b7feab8799385105730cb37946b28030f"
      ),
    };

    for (int index = 0; index < messageLengths.length; index++) {
      byte[] message = new byte[messageLengths[index]];

      for (int offset = 0; offset < message.length; offset++) {
        message[offset] = (byte) offset;
      }

      for (boolean messageFirst : new boolean[] { false, true }) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map((short) 5);
        {
          if (messageFirst) {
            writer.text("message".getBytes());
            writer.bytes(message);
          }

          writer.text("index".getBytes());
          writer.bytes(TEST_SEED_INDEX);
          writer.text("type".getBytes());
          writer.text("seed".getBytes());
          writeDerivation(writer, true, Hex.decode("8000002c800001f58000000080000000"));
          writer.text("cipher".getBytes());
          writer.text("ed25519".getBytes());

          if (!messageFirst) {
            writer.text("message".getBytes());
            writer.bytes(message);
          }
        }

        byte[] request = writer.getDataBuffer();

        if (message.length == 8078) {
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
        Assertions.assertTrue(simulator.selectApplet(MONOID_IDENTITY_AID));
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
    assertInvalidResponseHeaders(manager);

    ByteArrayOutputStream responseData = new ByteArrayOutputStream();
    ResponseAPDU part = first;

    while (true) {
      Assertions.assertTrue(part.getData().length > 0 && part.getData().length <= 256);
      responseData.write(part.getData());

      if (part.getSW() == 0x9000) {
        break;
      }

      Assertions.assertEquals(0x6100, part.getSW() & 0xFF00);
      part = transmitFrame(manager, 0, 0xC0, 0, 0, new byte[0]);
    }

    byte[] response = responseData.toByteArray();
    assertNoError(response);

    CBORBufferReader reader = new CBORBufferReader(response);
    reader.map();
    Assertions.assertEquals(8, reader.requireKey("items".getBytes()).array());
    Assertions.assertTrue(reader.index((short) 7));
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
      assertHello(response, true);
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

  @Test
  // @inplate-line {{java-test-order}}
  @Order(25)
  public void importedED25519Items() throws Exception {
    CardManager manager = connect();
    authenticate(manager, false);

    // RFC 8032, section 7.1, test 1; zero is also a valid private key seed.
    byte[] seed = Hex.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

    for (int mode = 0; mode < 3; mode++) {
      byte[] data = mode == 1 ? new byte[32] : seed;
      byte[] index = ed25519Index(data);
      CBORBufferWriter writer = new CBORBufferWriter();
      writer.map((short) 2);
      {
        writer.text(mode == 2 ? "index".getBytes() : "type".getBytes());

        if (mode == 0) {
          writer.text("ed25519".getBytes());
        } else if (mode == 1) {
          writer.integer((short) 0x0401);
        } else {
          writer.bytes(index);
        }

        writer.text("data".getBytes());
        writer.bytes(data);
      }

      ResponseAPDU response = manager.transmit(apdu(0, 0x34, 0, 0, writer.getDataBuffer()));
      assertNoError(response);
      CBORBufferReader reader = new CBORBufferReader(response.getBytes());
      reader.map();
      Assertions.assertArrayEquals(index, reader.requireKey("index".getBytes()).bytes());

      try {
        assertED25519Item(manager, index, data, new byte[0]);
      } finally {
        assertNoError(manager.transmit(apdu(0, 0x35, 0, 0, itemRequest(index))));
      }
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(26)
  public void randomED25519Item() throws Exception {
    CardManager manager = connect();
    authenticate(manager, false);

    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 1);
    writer.text("type".getBytes());
    writer.text("ed25519".getBytes());

    ResponseAPDU response = manager.transmit(apdu(0, 0x38, 0, 0, writer.getDataBuffer()));
    assertNoError(response);
    CBORBufferReader reader = new CBORBufferReader(response.getBytes());
    reader.map();
    byte[] index = reader.requireKey("index".getBytes()).bytes();

    try {
      assertED25519Item(manager, index, null, Hex.decode("72"));
    } finally {
      assertNoError(manager.transmit(apdu(0, 0x35, 0, 0, itemRequest(index))));
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(27)
  public void invalidED25519Items() throws Exception {
    CardManager manager = connect();
    authenticate(manager, false);

    byte[] invalidType = new byte[263];
    Arrays.fill(invalidType, (byte) 'x');
    System.arraycopy("ed25519".getBytes(), 0, invalidType, 0, 7);

    for (int instruction : new int[] { 0x30, 0x34, 0x38 }) {
      CBORBufferWriter writer = new CBORBufferWriter();
      writer.map((short) (instruction == 0x34 ? 2 : 1));
      writer.text("type".getBytes());
      writer.text(invalidType);

      if (instruction == 0x34) {
        writer.text("data".getBytes());
        writer.bytes(new byte[32]);
      }

      assertError(
        transmitFragments(manager, instruction, writer.getDataBuffer(), 255),
        MonoidException.CODE_INVALID_PARAMETER
      );
    }

    for (int length : new int[] { 0, 31, 33, 64 }) {
      byte[] data = new byte[length];

      for (boolean explicitIndex : new boolean[] { false, true }) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map((short) 2);

        if (explicitIndex) {
          writer.text("index".getBytes());
          writer.bytes(ed25519Index(data));
        } else {
          writer.text("type".getBytes());
          writer.text("ed25519".getBytes());
        }

        writer.text("data".getBytes());
        writer.bytes(data);
        assertError(
          manager.transmit(apdu(0, 0x34, 0, 0, writer.getDataBuffer())),
          SafeException.CODE_INVALID_PARAMETER
        );
      }
    }

    byte[] data = new byte[32];
    byte[] index = ed25519Index(data);
    index[9] ^= 1;
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    writer.text("index".getBytes());
    writer.bytes(index);
    writer.text("data".getBytes());
    writer.bytes(data);
    assertError(
      manager.transmit(apdu(0, 0x34, 0, 0, writer.getDataBuffer())),
      SafeException.CODE_INVALID_PARAMETER
    );

    index[9] ^= 1;
    writer.reset();
    writer.map((short) 2);
    writer.text("index".getBytes());
    writer.bytes(index);
    writer.text("data".getBytes());
    writer.bytes(data);
    assertNoError(manager.transmit(apdu(0, 0x34, 0, 0, writer.getDataBuffer())));

    try {
      for (boolean ecdsa : new boolean[] { false, true }) {
        writer.reset();
        writer.map((short) 4);
        writer.text("index".getBytes());
        writer.bytes(ecdsa ? index : TEST_SECP256K1_KEY_INDEX);
        writer.text("type".getBytes());
        writer.text(ecdsa ? "ed25519".getBytes() : "secp256k1".getBytes());
        writer.text("cipher".getBytes());
        writer.text(ecdsa ? "ecdsa".getBytes() : "ed25519".getBytes());
        writer.text(ecdsa ? "digest".getBytes() : "message".getBytes());
        writer.bytes(TEST_DIGEST);
        assertError(
          manager.transmit(apdu(0, 0x41, 0, 0, writer.getDataBuffer())),
          MonoidException.CODE_INVALID_PARAMETER
        );
      }
    } finally {
      assertNoError(manager.transmit(apdu(0, 0x35, 0, 0, itemRequest(index))));
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(28)
  public void importedSECP256r1Items() throws Exception {
    CardManager manager = connect();
    authenticate(manager, true);
    BigInteger order = SECNamedCurves.getByName("secp256r1").getN();

    for (BigInteger scalar : new BigInteger[] { BigInteger.ONE, order.subtract(BigInteger.ONE) }) {
      byte[] data = BigIntegers.asUnsignedByteArray(32, scalar);
      byte[] index = secp256r1Index(data);

      for (int mode = 0; mode < 3; mode++) {
        ResponseAPDU response = manager.transmit(
          apdu(0, 0x34, 0, 0, secp256r1CreateRequest(data, mode))
        );
        assertNoError(response);
        CBORBufferReader reader = new CBORBufferReader(response.getBytes());
        reader.map();
        Assertions.assertArrayEquals(index, reader.requireKey("index".getBytes()).bytes());

        try {
          response = manager.transmit(apdu(0, 0x32, 0, 0, itemRequest(index)));
          assertNoError(response);
          reader = new CBORBufferReader(response.getBytes());
          reader.map();
          Assertions.assertArrayEquals(data, reader.requireKey("data".getBytes()).bytes());

          CBORBufferWriter writer = new CBORBufferWriter();
          writer.map((short) 1);
          writer.text("type".getBytes());
          writer.text("secp256r1".getBytes());
          response = manager.transmit(apdu(0, 0x30, 0, 0, writer.getDataBuffer()));
          assertNoError(response);
          reader = new CBORBufferReader(response.getBytes());
          reader.map();
          Assertions.assertEquals(1, reader.requireKey("items".getBytes()).array());
          Assertions.assertTrue(reader.index((short) 0));
          reader.map();
          Assertions.assertArrayEquals(index, reader.requireKey("index".getBytes()).bytes());
          Assertions.assertArrayEquals(
            "secp256r1".getBytes(),
            reader.requireKey("type".getBytes()).text()
          );

          assertSECP256r1Item(manager, index, data);
        } finally {
          assertNoError(manager.transmit(apdu(0, 0x35, 0, 0, itemRequest(index))));
        }
      }
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(29)
  public void randomSECP256r1Item() throws Exception {
    CardManager manager = connect();
    authenticate(manager, false);
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 1);
    writer.text("type".getBytes());
    writer.text("secp256r1".getBytes());

    ResponseAPDU response = manager.transmit(apdu(0, 0x38, 0, 0, writer.getDataBuffer()));
    assertNoError(response);
    CBORBufferReader reader = new CBORBufferReader(response.getBytes());
    reader.map();
    byte[] index = reader.requireKey("index".getBytes()).bytes();

    try {
      for (boolean safeAuth : new boolean[] { false, true }) {
        authenticate(manager, safeAuth);
        assertError(
          manager.transmit(apdu(0, 0x32, 0, 0, itemRequest(index))),
          MonoidException.CODE_ACCESS_DENIED
        );
      }

      response = manager.transmit(apdu(0, 0x31, 0, 0, itemRequest(index)));
      assertNoError(response);
      reader = new CBORBufferReader(response.getBytes());
      reader.map();
      Assertions.assertTrue(reader.requireKey("secret".getBytes()).bool());

      assertSECP256r1Item(manager, index, null);
    } finally {
      assertNoError(manager.transmit(apdu(0, 0x35, 0, 0, itemRequest(index))));
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(30)
  public void invalidSECP256r1Items() throws Exception {
    CardManager manager = connect();
    authenticate(manager, false);
    BigInteger order = SECNamedCurves.getByName("secp256r1").getN();

    for (byte[] data : new byte[][] {
      new byte[0],
      new byte[31],
      new byte[32],
      new byte[33],
      new byte[64],
      BigIntegers.asUnsignedByteArray(32, order),
      BigIntegers.asUnsignedByteArray(32, order.add(BigInteger.ONE)),
      BigIntegers.asUnsignedByteArray(32, BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)),
    }) {
      for (int mode = 0; mode < 3; mode++) {
        assertError(
          manager.transmit(apdu(0, 0x34, 0, 0, secp256r1CreateRequest(data, mode))),
          SafeException.CODE_INVALID_PARAMETER
        );
      }
    }

    byte[] validData = BigIntegers.asUnsignedByteArray(32, BigInteger.ONE);
    byte[] index = secp256r1Index(validData);
    index[9] ^= 1;
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    writer.text("index".getBytes());
    writer.bytes(index);
    writer.text("data".getBytes());
    writer.bytes(validData);
    assertError(
      manager.transmit(apdu(0, 0x34, 0, 0, writer.getDataBuffer())),
      SafeException.CODE_INVALID_PARAMETER
    );
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(31)
  public void invalidSECP256r1SigningRequests() throws Exception {
    CardManager manager = connect();
    authenticate(manager, false);
    byte[] data = BigIntegers.asUnsignedByteArray(32, BigInteger.ONE);
    byte[] index = secp256r1Index(data);
    assertNoError(manager.transmit(apdu(0, 0x34, 0, 0, secp256r1CreateRequest(data, 0))));

    try {
      for (String cipher : new String[] { "ed25519", "bip340" }) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map((short) 4);
        writer.text("index".getBytes());
        writer.bytes(index);
        writer.text("type".getBytes());
        writer.text("secp256r1".getBytes());
        writer.text("cipher".getBytes());
        writer.text(cipher.getBytes());
        writer.text(cipher.equals("ed25519") ? "message".getBytes() : "digest".getBytes());
        writer.bytes(TEST_DIGEST);
        assertError(
          manager.transmit(apdu(0, 0x41, 0, 0, writer.getDataBuffer())),
          MonoidException.CODE_INVALID_PARAMETER
        );
      }

      for (int instruction : new int[] { 0x40, 0x41 }) {
        for (int mode = 0; mode < 4; mode++) {
          CBORBufferWriter writer = new CBORBufferWriter();
          writer.map((short) (instruction == 0x41 ? 5 : 3));
          writer.text("index".getBytes());
          writer.bytes(index);
          writer.text("type".getBytes());
          writer.text("secp256r1".getBytes());

          if (instruction == 0x41) {
            writer.text("cipher".getBytes());
            writer.text("ecdsa".getBytes());
            writer.text("digest".getBytes());
            writer.bytes(TEST_DIGEST);
          }

          writer.text("taproot".getBytes());

          if (mode < 2) {
            writer.bool(mode == 1);
          } else {
            writer.map((short) (mode == 2 ? 0 : 1));

            if (mode == 3) {
              writer.text("merkleRoot".getBytes());
              writer.bytes(new byte[32]);
            }
          }

          assertError(
            manager.transmit(apdu(0, instruction, 0, 0, writer.getDataBuffer())),
            MonoidException.CODE_INVALID_PARAMETER
          );
        }
      }

      for (int length : new int[] { 0, 31, 33, 64 }) {
        assertError(
          manager.transmit(apdu(0, 0x41, 0, 0, ecdsaRequest(index, new byte[length], false))),
          MonoidException.CODE_INVALID_PARAMETER
        );
      }

      assertSECP256r1Item(manager, index, data);

      assertSignature(
        manager.transmit(
          apdu(0, 0x41, 0, 0, ecdsaRequest(TEST_SECP256K1_KEY_INDEX, TEST_DIGEST, false))
        ),
        TEST_DIGEST,
        TEST_SECP256K1_DERIVED_PUBLIC_KEY
      );

      CBORBufferWriter writer = new CBORBufferWriter();
      writer.map((short) 4);
      writer.text("index".getBytes());
      writer.bytes(TEST_ED25519_KEY_INDEX);
      writer.text("type".getBytes());
      writer.text("ed25519".getBytes());
      writer.text("cipher".getBytes());
      writer.text("ed25519".getBytes());
      writer.text("message".getBytes());
      writer.bytes(Hex.decode("72"));
      ResponseAPDU response = manager.transmit(apdu(0, 0x41, 0, 0, writer.getDataBuffer()));
      assertNoError(response);
      CBORBufferReader reader = new CBORBufferReader(response.getBytes());
      reader.map();
      Assertions.assertArrayEquals(
        Hex.decode(
          "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
          "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
        reader.requireKey("signature".getBytes()).bytes()
      );

      assertSECP256r1Item(manager, index, data);
    } finally {
      assertNoError(manager.transmit(apdu(0, 0x35, 0, 0, itemRequest(index))));
    }
  }

  @Test
  // @inplate-line {{java-test-order}}
  @Order(32)
  public void rejectSECP256r1Derivation() throws Exception {
    CardManager manager = connect();
    authenticate(manager, false);

    for (byte[] path : new byte[][] { new byte[0], TEST_PATH }) {
      for (int instruction : new int[] { 0x40, 0x41 }) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map((short) (instruction == 0x41 ? 5 : 3));
        writer.text("index".getBytes());
        writer.bytes(TEST_SEED_INDEX);
        writer.text("type".getBytes());
        writer.text("seed".getBytes());
        writer.text("derivation".getBytes());
        writer.map((short) 3);
        writer.text("type".getBytes());
        writer.text("slip10".getBytes());
        writer.text("curve".getBytes());
        writer.text("secp256r1".getBytes());
        writer.text("path".getBytes());
        writer.bytes(path);

        if (instruction == 0x41) {
          writer.text("cipher".getBytes());
          writer.text("ecdsa".getBytes());
          writer.text("digest".getBytes());
          writer.bytes(TEST_DIGEST);
        }

        assertError(
          manager.transmit(apdu(0, instruction, 0, 0, writer.getDataBuffer())),
          MonoidException.CODE_INVALID_PARAMETER
        );
      }
    }

    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 3);
    writer.text("index".getBytes());
    writer.bytes(TEST_SEED_INDEX);
    writer.text("type".getBytes());
    writer.text("seed".getBytes());
    writeDerivation(writer, false, TEST_PATH);
    ResponseAPDU response = manager.transmit(apdu(0, 0x40, 0, 0, writer.getDataBuffer()));
    assertNoError(response);
    CBORBufferReader reader = new CBORBufferReader(response.getBytes());
    reader.map();
    Assertions.assertArrayEquals(
      TEST_SEED_DERIVED_PUBLIC_KEY,
      reader.requireKey("publicKey".getBytes()).bytes()
    );
    Assertions.assertArrayEquals(
      TEST_SEED_DERIVED_CHAIN_CODE,
      reader.requireKey("chainCode".getBytes()).bytes()
    );
  }

  private byte[] secp256r1CreateRequest(byte[] data, int mode) throws Exception {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    writer.text(mode == 2 ? "index".getBytes() : "type".getBytes());

    if (mode == 0) {
      writer.text("secp256r1".getBytes());
    } else if (mode == 1) {
      writer.integer((short) 0x0302);
    } else {
      writer.bytes(secp256r1Index(data));
    }

    writer.text("data".getBytes());
    writer.bytes(data);
    return writer.getDataBuffer();
  }

  private byte[] secp256r1Index(byte[] data) throws Exception {
    byte[] index = new byte[10];
    index[0] = 0x03;
    index[1] = 0x02;
    System.arraycopy(MessageDigest.getInstance("SHA-256").digest(data), 0, index, 2, 8);
    return index;
  }

  private byte[] ed25519Index(byte[] data) throws Exception {
    byte[] index = new byte[10];
    index[0] = 0x04;
    index[1] = 0x01;
    System.arraycopy(MessageDigest.getInstance("SHA-256").digest(data), 0, index, 2, 8);
    return index;
  }

  private byte[] itemRequest(byte[] index) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 1);
    writer.text("index".getBytes());
    writer.bytes(index);
    return writer.getDataBuffer();
  }

  private byte[] ecdsaRequest(byte[] index, byte[] digest, boolean explicitTaproot) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (explicitTaproot ? 5 : 4));
    writer.text("index".getBytes());
    writer.bytes(index);
    writer.text("type".getBytes());
    writer.text(index[1] == 2 ? "secp256r1".getBytes() : "secp256k1".getBytes());
    writer.text("cipher".getBytes());
    writer.text("ecdsa".getBytes());
    writer.text("digest".getBytes());
    writer.bytes(digest);

    if (explicitTaproot) {
      writer.text("taproot".getBytes());
      writer.bool(false);
    }

    return writer.getDataBuffer();
  }

  private void assertSECP256r1Item(CardManager manager, byte[] index, byte[] data)
    throws Exception {
    X9ECParameters parameters = SECNamedCurves.getByName("secp256r1");

    for (boolean explicitTaproot : new boolean[] { false, true }) {
      CBORBufferWriter writer = new CBORBufferWriter();
      writer.map((short) (explicitTaproot ? 3 : 2));
      writer.text("index".getBytes());
      writer.bytes(index);
      writer.text("type".getBytes());
      writer.text("secp256r1".getBytes());

      if (explicitTaproot) {
        writer.text("taproot".getBytes());
        writer.bool(false);
      }

      ResponseAPDU response = manager.transmit(apdu(0, 0x40, 0, 0, writer.getDataBuffer()));

      if (explicitTaproot) {
        assertError(response, MonoidException.CODE_INVALID_PARAMETER);
        assertError(
          manager.transmit(apdu(0, 0x41, 0, 0, ecdsaRequest(index, TEST_DIGEST, true))),
          MonoidException.CODE_INVALID_PARAMETER
        );
        continue;
      }

      assertNoError(response);
      CBORBufferReader reader = new CBORBufferReader(response.getBytes());
      Assertions.assertEquals(1, reader.map());
      byte[] publicKey = reader.requireKey("publicKey".getBytes()).bytes();
      Assertions.assertTrue(parameters.getCurve().decodePoint(publicKey).isValid());

      if (data != null) {
        Assertions.assertArrayEquals(
          parameters.getG().multiply(new BigInteger(1, data)).getEncoded(true),
          publicKey
        );
      }

      Assertions.assertFalse(reader.key("chainCode".getBytes()));

      response = manager.transmit(
        apdu(0, 0x41, 0, 0, ecdsaRequest(index, TEST_DIGEST, explicitTaproot))
      );

      assertNoError(response);
      reader = new CBORBufferReader(response.getBytes());
      Assertions.assertEquals(1, reader.map());
      byte[] signature = reader.requireKey("signature".getBytes()).bytes();
      Assertions.assertEquals(64, signature.length);
      BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));
      BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));
      Assertions.assertTrue(s.compareTo(parameters.getN().shiftRight(1)) <= 0);

      ECDSASigner verifier = new ECDSASigner();
      verifier.init(
        false,
        new ECPublicKeyParameters(
          parameters.getCurve().decodePoint(publicKey),
          new ECDomainParameters(
            parameters.getCurve(),
            parameters.getG(),
            parameters.getN(),
            parameters.getH()
          )
        )
      );
      Assertions.assertTrue(verifier.verifySignature(TEST_DIGEST, r, s));
    }
  }

  private void assertED25519Item(CardManager manager, byte[] index, byte[] seed, byte[] message)
    throws Exception {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 1);
    writer.text("type".getBytes());
    writer.text("ed25519".getBytes());

    ResponseAPDU response = manager.transmit(apdu(0, 0x30, 0, 0, writer.getDataBuffer()));
    assertNoError(response);
    CBORBufferReader reader = new CBORBufferReader(response.getBytes());
    reader.map();
    short count = reader.requireKey("items".getBytes()).array();
    Assertions.assertEquals(2, count);
    boolean foundExample = false;
    boolean foundItem = false;

    for (short item = 0; item < count; item++) {
      Assertions.assertTrue(reader.index(item));
      reader.map();
      Assertions.assertArrayEquals(
        "ed25519".getBytes(),
        reader.requireKey("type".getBytes()).text()
      );
      byte[] listedIndex = reader.requireKey("index".getBytes()).bytes();
      foundExample |= Arrays.equals(TEST_ED25519_KEY_INDEX, listedIndex);
      foundItem |= Arrays.equals(index, listedIndex);

      if (Arrays.equals(index, listedIndex)) {
        Assertions.assertEquals(seed == null, reader.requireKey("secret".getBytes()).bool());
      }
    }

    Assertions.assertTrue(foundExample);
    Assertions.assertTrue(foundItem);

    for (short category : new short[] { 0x0300, 0x0400 }) {
      writer.reset();
      writer.map((short) 1);
      writer.text("type".getBytes());
      writer.integer(category);

      response = manager.transmit(apdu(0, 0x30, 0, 0, writer.getDataBuffer()));
      assertNoError(response);
      reader = new CBORBufferReader(response.getBytes());
      reader.map();
      count = reader.requireKey("items".getBytes()).array();
      Assertions.assertEquals(2, count);

      for (short item = 0; item < count; item++) {
        Assertions.assertTrue(reader.index(item));
        reader.map();
        byte[] listedIndex = reader.requireKey("index".getBytes()).bytes();
        Assertions.assertEquals(category >> 8, listedIndex[0]);
        Assertions.assertEquals(0x01, listedIndex[1]);
      }
    }

    authenticate(manager, true);
    response = manager.transmit(apdu(0, 0x32, 0, 0, itemRequest(index)));

    if (seed == null) {
      assertError(response, MonoidException.CODE_ACCESS_DENIED);
    } else {
      assertNoError(response);
      reader = new CBORBufferReader(response.getBytes());
      reader.map();
      Assertions.assertArrayEquals(seed, reader.requireKey("data".getBytes()).bytes());
    }

    writer.reset();
    writer.map((short) 2);
    writer.text("index".getBytes());
    writer.bytes(index);
    writer.text("type".getBytes());
    writer.text("ed25519".getBytes());
    response = manager.transmit(apdu(0, 0x40, 0, 0, writer.getDataBuffer()));
    assertNoError(response);
    reader = new CBORBufferReader(response.getBytes());
    Assertions.assertEquals(1, reader.map());
    byte[] publicKey = reader.requireKey("publicKey".getBytes()).bytes();
    Assertions.assertEquals(32, publicKey.length);
    Assertions.assertFalse(reader.key("chainCode".getBytes()));

    writer.reset();
    writer.map((short) 4);
    writer.text("index".getBytes());
    writer.bytes(index);
    writer.text("type".getBytes());
    writer.text("ed25519".getBytes());
    writer.text("cipher".getBytes());
    writer.text("ed25519".getBytes());
    writer.text("message".getBytes());
    writer.bytes(message);
    response = manager.transmit(apdu(0, 0x41, 0, 0, writer.getDataBuffer()));
    assertNoError(response);
    reader = new CBORBufferReader(response.getBytes());
    Assertions.assertEquals(1, reader.map());
    byte[] signature = reader.requireKey("signature".getBytes()).bytes();
    Assertions.assertEquals(64, signature.length);

    Process process = new ProcessBuilder(
      "node",
      "-e",
      "const c = require('node:crypto'); " +
      "const [seed, pub, msg, sig] = process.argv.slice(1).map(x => Buffer.from(x, 'hex')); " +
      "const publicKey = c.createPublicKey({key: Buffer.concat([" +
      "Buffer.from('302a300506032b6570032100', 'hex'), pub]), " +
      "format: 'der', type: 'spki'}); " +
      "if (!c.verify(null, msg, publicKey, sig)) process.exit(1); " +
      "if (seed.length) { const key = c.createPrivateKey({key: Buffer.concat([" +
      "Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), " +
      "format: 'der', type: 'pkcs8'}); " +
      "const expected = c.createPublicKey(key).export({format: 'der', type: 'spki'}).subarray(-32); " +
      "if (!expected.equals(pub) || !c.sign(null, msg, key).equals(sig)) process.exit(1); }",
      seed != null ? Hex.toHexString(seed) : "",
      Hex.toHexString(publicKey),
      Hex.toHexString(message),
      Hex.toHexString(signature)
    )
      .inheritIO()
      .start();

    Assertions.assertEquals(0, process.waitFor());
  }

  private void writeDerivation(CBORBufferWriter writer, boolean ed25519, byte[] path) {
    writer.text("derivation".getBytes());
    writer.map((short) (ed25519 ? 3 : 2));
    writer.text("type".getBytes());
    writer.text(ed25519 ? "slip10".getBytes() : "bip32".getBytes());

    if (ed25519) {
      writer.text("curve".getBytes());
      writer.text("ed25519".getBytes());
    }

    writer.text("path".getBytes());
    writer.bytes(path);
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

  private void assertHello(ResponseAPDU response, boolean pinsSet) {
    CBORBufferReader reader = new CBORBufferReader(response.getBytes());
    Assertions.assertEquals(5, reader.map());
    reader.requireKey("version".getBytes()).integer();
    Assertions.assertEquals(4, reader.requireKey("id".getBytes()).bytes().length);

    byte[] publicKey = reader.requireKey("publicKey".getBytes()).bytes();
    Assertions.assertEquals(65, publicKey.length);
    Assertions.assertEquals(0x04, publicKey[0]);
    Assertions.assertFalse(reader.requireKey("bundle".getBytes()).bool());

    Assertions.assertEquals(2, reader.requireKey("pins".getBytes()).map());
    for (String pin : new String[] { "access", "secret" }) {
      reader.requireKey(pin.getBytes());
      if (pinsSet) {
        Assertions.assertTrue(reader.integer() > 0);
      } else {
        Assertions.assertFalse(reader.bool());
      }
    }
  }

  private void assertFeatures(ResponseAPDU response) {
    String[] curves = { "secp256k1", "secp256r1", "ed25519" };
    String[][] ciphers = { { "ecdsa", "bip340" }, { "ecdsa" }, { "ed25519" } };

    for (short index = 0; index < curves.length; index++) {
      CBORBufferReader reader = new CBORBufferReader(response.getBytes());
      reader.map();
      Assertions.assertEquals(1, reader.requireKey("features".getBytes()).map());
      Assertions.assertEquals(3, reader.requireKey("curves".getBytes()).array());
      reader.index(index);
      Assertions.assertEquals(2, reader.map());
      Assertions.assertArrayEquals(
        curves[index].getBytes(),
        reader.requireKey("name".getBytes()).text()
      );
      Assertions.assertEquals(
        ciphers[index].length,
        reader.requireKey("ciphers".getBytes()).array()
      );

      for (short cipher = 0; cipher < ciphers[index].length; cipher++) {
        reader.index(cipher);
        Assertions.assertArrayEquals(ciphers[index][cipher].getBytes(), reader.text());
      }
    }
  }

  private void assertSignature(ResponseAPDU response, byte[] digest, byte[] publicKey)
    throws IOException, InterruptedException {
    assertNoError(response);

    CBORBufferReader reader = new CBORBufferReader(response.getBytes());
    reader.map();

    byte[] signature = reader.requireKey("signature".getBytes()).bytes();

    System.out.println(String.format("Signature: %s", Hex.toHexString(signature)));

    Assertions.assertEquals(64, signature.length);

    crossVerifySignature(signature, digest, publicKey);
  }

  private void authenticate(CardManager manager, boolean safeAuth)
    throws javax.smartcardio.CardException {
    CBORBufferWriter writer = new CBORBufferWriter();

    writer.map((short) (safeAuth ? 2 : 1));
    {
      writer.text("pin".getBytes());
      writer.text(safeAuth ? SECRET_PIN : PIN);

      if (safeAuth) {
        writer.text("secret".getBytes());
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
