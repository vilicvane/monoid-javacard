package tests;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.utils.AIDUtil;
import cz.muni.fi.crocs.rcard.client.CardType;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.framework.AID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.ResponseAPDU;
import monoid.CBORBufferReader;
import monoid.CBORBufferWriter;
import monoid.Command;
import monoid.DerivedKey;
import monoid.Monoid001Derivation;
import monoid.MonoidApplet;
import monoid.MonoidException;
import monoid.WeierstrassCurve;
import monoidsafe.MonoidSafeApplet;
import monoidsafeidentity.MonoidSafeIdentityApplet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class Monoid001Test extends AppletTest {

  private static final AID MONOID_SAFE_IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_IDENTITY_AID}}"
    "f06d6f6e6f696400010000"
  );
  private static final AID MONOID_SAFE_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_AID}}"
    "f06d6f6e6f696401010000"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f696402010000"
  );

  private static final byte[] PIN = "888888".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] SALT = "Monoid-001".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] SEED = Hex.decode(
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
  );
  private static final byte[] DIGEST = Hex.decode(
    "43ddcab065bcc7bd8d80c479ed29d3658ccf3ac3343b7044013008bde5ca19cf"
  );

  public Monoid001Test() {
    super(MONOID_AID, CardType.JCARDSIMLOCAL);
  }

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.bouncycastle.rsa.allow_unsafe_mod", "true");
    resetAppletState();

    simulator.installApplet(MONOID_SAFE_IDENTITY_AID, MonoidSafeIdentityApplet.class);
    simulator.installApplet(MONOID_SAFE_AID, MonoidSafeApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));

    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    writer.text("pin".getBytes());
    writer.text(PIN);
    writer.text("safe".getBytes());
    writer.bool(true);
    assertNoError(transmit(0x22, writer.getDataBuffer()));
    authenticate(false);
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(MONOID_AID);
    simulator.deleteApplet(MONOID_SAFE_AID);
    simulator.deleteApplet(MONOID_SAFE_IDENTITY_AID);
    resetAppletState();
  }

  private void resetAppletState() {
    // Separate simulator instances share Java static fields within the test JVM.
    MonoidApplet.version = 0;
    MonoidApplet.safe = null;
    MonoidApplet.safePIN = null;
    MonoidApplet.keystore = null;
  }

  @Test
  public void seedAndMasterDeriveTheSameContextKeys() throws Exception {
    byte[] master = hmac(SALT, SEED);
    byte[] seedIndex = create("seed", SEED);
    byte[] masterIndex = create("master", master);
    byte[] previous = null;

    for (byte[] context : new byte[][] {
      new byte[0],
      "credential-01".getBytes(StandardCharsets.US_ASCII),
      Hex.decode("00ff80000102030405060708090a0b0c0d"),
      Hex.decode("00ff80000102030405060708090a0b0c0e"),
    }) {
      byte[] expected = publicKey(master, context);
      assertPublicKey(transmit(0x40, keyRequest(seedIndex, "seed", context, null)), expected);
      assertPublicKey(transmit(0x40, keyRequest(masterIndex, "master", context, null)), expected);

      if (previous != null) {
        Assertions.assertFalse(Arrays.equals(previous, expected));
      }

      previous = expected;
    }

    authenticate(true);
    Assertions.assertArrayEquals(SEED, field(transmit(0x32, itemRequest(seedIndex)), "data"));
    Assertions.assertArrayEquals(master, field(transmit(0x32, itemRequest(masterIndex)), "data"));
  }

  @Test
  public void derivedWorkingCopiesSurviveDeselectAndClearOnReset() throws Exception {
    byte[] context = Hex.decode("007f80ff0001");
    byte[] master = hmac(SALT, SEED);
    byte[] expectedKey = privateKey(master, context);
    byte[] expectedPublicKey = publicKey(master, context);
    Monoid001Derivation derivation = new Monoid001Derivation();
    DerivedKey derived = derivation.deriveFromSeed(SEED, context);
    byte[][] workingKeys = { derived.getKey(), derived.getKey() };
    byte[][] workingPublicKeys = {
      derived.getPublicKey(WeierstrassCurve.secp256r1),
      derived.getPublicKey(WeierstrassCurve.secp256r1),
    };

    Assertions.assertNotSame(workingKeys[0], workingKeys[1]);
    Assertions.assertNotSame(workingPublicKeys[0], workingPublicKeys[1]);
    Assertions.assertTrue(simulator.selectApplet(MONOID_SAFE_AID));
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));

    for (byte[] key : workingKeys) {
      Assertions.assertArrayEquals(expectedKey, key);
    }

    for (byte[] key : workingPublicKeys) {
      Assertions.assertArrayEquals(expectedPublicKey, key);
    }

    simulator.reset();

    for (byte[] key : workingKeys) {
      Assertions.assertArrayEquals(new byte[key.length], key);
    }

    for (byte[] key : workingPublicKeys) {
      Assertions.assertArrayEquals(new byte[key.length], key);
    }

    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    DerivedKey recovered = derivation.deriveFromSeed(SEED, context);
    Assertions.assertArrayEquals(expectedKey, recovered.getKey());
    Assertions.assertArrayEquals(
      expectedPublicKey,
      recovered.getPublicKey(WeierstrassCurve.secp256r1)
    );
  }

  @Test
  public void fragmentedRequestsRestoreRootFields() throws Exception {
    byte[] index = create("seed", SEED);
    byte[] context = new byte[96];

    for (int i = 0; i < context.length; i++) {
      context[i] = (byte) i;
    }

    for (int instruction : new int[] { 0x40, 0x41 }) {
      CBORBufferWriter writer = new CBORBufferWriter();
      writer.map((short) (instruction == 0x40 ? 3 : 5));
      writer.text("derivation".getBytes());
      writer.map((short) 2);
      writer.text("context".getBytes());
      writer.bytes(context);
      writer.text("type".getBytes());
      writer.text("monoid-001".getBytes());

      if (instruction == 0x41) {
        writeSigning(writer, "ecdsa");
      }

      writeKey(writer, index, "seed");
      ResponseAPDU response = transmitFragments(instruction, writer.getDataBuffer(), 37);

      if (instruction == 0x40) {
        assertPublicKey(response, publicKey(hmac(SALT, SEED), context));
      } else {
        // jCardSim cannot sign an ECDSA precomputed hash; this only checks dispatch.
        assertError(response, Command.CODE_INTERNAL);
      }
    }
  }

  @Test
  public void derivedEcdsaUsesTheExistingSimulatorSigningPath() throws Exception {
    byte[] master = hmac(SALT, SEED);
    byte[] context = Hex.decode("0102030405060708");
    byte[] seedIndex = create("seed", SEED);
    byte[] masterIndex = create("master", master);
    byte[] directIndex = create("secp256r1", privateKey(master, context));

    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 4);
    writeKey(writer, directIndex, "secp256r1");
    writeSigning(writer, "ecdsa");

    // Successful signature verification requires a physical card: jCardSim lacks this API.
    assertError(transmit(0x41, writer.getDataBuffer()), Command.CODE_INTERNAL);
    assertError(
      transmit(0x41, keyRequest(seedIndex, "seed", context, "ecdsa")),
      Command.CODE_INTERNAL
    );
    assertError(
      transmit(0x41, keyRequest(masterIndex, "master", context, "ecdsa")),
      Command.CODE_INTERNAL
    );

    assertPublicKey(
      transmit(0x40, keyRequest(seedIndex, "seed", context, null)),
      publicKey(master, context)
    );
    authenticate(true);
    Assertions.assertArrayEquals(SEED, field(transmit(0x32, itemRequest(seedIndex)), "data"));
    Assertions.assertArrayEquals(master, field(transmit(0x32, itemRequest(masterIndex)), "data"));
  }

  @Test
  public void rejectCurveAndPathOverridesAndLegacyName() throws Exception {
    byte[] index = create("seed", SEED);

    for (int instruction : new int[] { 0x40, 0x41 }) {
      for (String invalid : new String[] { "curve", "path", "monoid-p256-v1" }) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map((short) (instruction == 0x40 ? 3 : 5));
        writeKey(writer, index, "seed");
        writer.text("derivation".getBytes());
        writer.map((short) (invalid.equals("monoid-p256-v1") ? 2 : 3));
        writer.text("type".getBytes());
        writer.text(
          (invalid.equals("monoid-p256-v1") ? "monoid-p256-v1" : "monoid-001").getBytes()
        );
        writer.text("context".getBytes());
        writer.bytes(new byte[0]);

        if (invalid.equals("curve")) {
          writer.text("curve".getBytes());
          writer.text("secp256r1".getBytes());
        } else if (invalid.equals("path")) {
          writer.text("path".getBytes());
          writer.bytes(new byte[0]);
        }

        if (instruction == 0x41) {
          writeSigning(writer, "ecdsa");
        }

        assertError(
          transmit(instruction, writer.getDataBuffer()),
          MonoidException.CODE_INVALID_PARAMETER
        );
      }
    }
  }

  @Test
  public void requireByteContextAndRejectTaprootAndOtherCiphers() throws Exception {
    byte[] index = create("seed", SEED);

    for (int instruction : new int[] { 0x40, 0x41 }) {
      for (boolean missing : new boolean[] { false, true }) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map((short) (instruction == 0x40 ? 3 : 5));
        writeKey(writer, index, "seed");
        writer.text("derivation".getBytes());
        writer.map((short) (missing ? 1 : 2));
        writer.text("type".getBytes());
        writer.text("monoid-001".getBytes());

        if (!missing) {
          writer.text("context".getBytes());
          writer.text(new byte[0]);
        }

        if (instruction == 0x41) {
          writeSigning(writer, "ecdsa");
        }

        Assertions.assertEquals(0x6A80, transmit(instruction, writer.getDataBuffer()).getSW());
      }

      for (int mode = 0; mode < 3; mode++) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map((short) (instruction == 0x40 ? 4 : 6));
        writeKey(writer, index, "seed");
        writeDerivation(writer, new byte[0]);
        writer.text("taproot".getBytes());

        if (mode < 2) {
          writer.bool(mode == 1);
        } else {
          writer.map((short) 0);
        }

        if (instruction == 0x41) {
          writeSigning(writer, "ecdsa");
        }

        assertError(
          transmit(instruction, writer.getDataBuffer()),
          MonoidException.CODE_INVALID_PARAMETER
        );
      }
    }

    for (String cipher : new String[] { "ed25519", "bip340" }) {
      assertError(
        transmit(0x41, keyRequest(index, "seed", new byte[0], cipher)),
        MonoidException.CODE_INVALID_PARAMETER
      );
    }
  }

  @Test
  public void rejectDerivationFromIndependentKeys() throws Exception {
    byte[] data = new byte[32];
    data[31] = 1;

    for (String type : new String[] { "secp256k1", "secp256r1", "ed25519" }) {
      byte[] index = create(type, data);

      for (int instruction : new int[] { 0x40, 0x41 }) {
        assertError(
          transmit(
            instruction,
            keyRequest(index, type, new byte[0], instruction == 0x41 ? "ecdsa" : null)
          ),
          MonoidException.CODE_INVALID_PARAMETER
        );
      }
    }
  }

  @Test
  public void resetRequiresAuthenticationAndPreservesDerivedKey() throws Exception {
    byte[] index = create("seed", SEED);
    byte[] context = Hex.decode("112233445566778899aabbccddeeff00");
    byte[] expected = publicKey(hmac(SALT, SEED), context);
    assertPublicKey(transmit(0x40, keyRequest(index, "seed", context, null)), expected);

    simulator.reset();
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));

    for (int instruction : new int[] { 0x40, 0x41 }) {
      assertError(
        transmit(
          instruction,
          keyRequest(index, "seed", context, instruction == 0x41 ? "ecdsa" : null)
        ),
        MonoidException.CODE_UNAUTHORIZED
      );
    }

    authenticate(false);
    assertPublicKey(transmit(0x40, keyRequest(index, "seed", context, null)), expected);
  }

  @Test
  public void updatingSourceDataAtTheSameIndexChangesTheDerivedKey() throws Exception {
    byte[] context = Hex.decode("0102030405");

    for (String type : new String[] { "seed", "master" }) {
      byte[] source = type.equals("seed") ? SEED.clone() : hmac(SALT, SEED);
      byte[] index = create(type, source);
      byte[] master = type.equals("seed") ? hmac(SALT, source) : source;
      byte[] original = publicKey(master, context);
      assertPublicKey(transmit(0x40, keyRequest(index, type, context, null)), original);
      assertPublicKey(transmit(0x40, keyRequest(index, type, context, null)), original);

      source[source.length - 1] ^= 1;
      CBORBufferWriter writer = new CBORBufferWriter();
      writer.map((short) 2);
      writer.text("index".getBytes());
      writer.bytes(index);
      writer.text("data".getBytes());
      writer.bytes(source);
      assertNoError(transmit(0x33, writer.getDataBuffer()));

      master = type.equals("seed") ? hmac(SALT, source) : source;
      byte[] updated = publicKey(master, context);
      Assertions.assertFalse(Arrays.equals(original, updated));
      assertPublicKey(transmit(0x40, keyRequest(index, type, context, null)), updated);
      Assertions.assertArrayEquals(source, field(transmit(0x32, itemRequest(index)), "data"));
    }
  }

  @Test
  public void deletedSourcesCannotBeUsedThroughTheDerivationCache() throws Exception {
    byte[] context = Hex.decode("0102030405");

    for (String type : new String[] { "seed", "master" }) {
      byte[] source = type.equals("seed") ? SEED.clone() : hmac(SALT, SEED);
      byte[] index = create(type, source);
      byte[] master = type.equals("seed") ? hmac(SALT, source) : source;
      assertPublicKey(
        transmit(0x40, keyRequest(index, type, context, null)),
        publicKey(master, context)
      );
      assertNoError(transmit(0x35, itemRequest(index)));

      for (int instruction : new int[] { 0x40, 0x41 }) {
        assertError(
          transmit(
            instruction,
            keyRequest(index, type, context, instruction == 0x41 ? "ecdsa" : null)
          ),
          MonoidException.CODE_NOT_FOUND
        );
      }
    }
  }

  private byte[] publicKey(byte[] master, byte[] context) throws Exception {
    return SECNamedCurves.getByName("secp256r1")
      .getG()
      .multiply(new BigInteger(1, privateKey(master, context)))
      .getEncoded(true);
  }

  private byte[] privateKey(byte[] master, byte[] context) throws Exception {
    X9ECParameters parameters = SECNamedCurves.getByName("secp256r1");
    byte[] input = new byte[SALT.length + 1 + context.length + 2];
    System.arraycopy(SALT, 0, input, 0, SALT.length);
    System.arraycopy(context, 0, input, SALT.length + 1, context.length);
    input[input.length - 1] = 1;

    // HKDF-Expand's first SHA-512 block is HMAC(PRK, info || 0x01).
    for (int retry = 0; retry < 256; retry++) {
      input[input.length - 2] = (byte) retry;
      byte[] candidate = Arrays.copyOf(hmac(master, input), 32);
      BigInteger scalar = new BigInteger(1, candidate);

      if (scalar.signum() > 0 && scalar.compareTo(parameters.getN()) < 0) {
        return candidate;
      }
    }

    throw new IllegalStateException("Monoid-001 rejection sampling exhausted");
  }

  private byte[] hmac(byte[] key, byte[] input) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA512");
    mac.init(new SecretKeySpec(key, "HmacSHA512"));
    return mac.doFinal(input);
  }

  private void authenticate(boolean safe) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (safe ? 2 : 1));
    writer.text("pin".getBytes());
    writer.text(PIN);

    if (safe) {
      writer.text("safe".getBytes());
      writer.bool(true);
    }

    assertNoError(transmit(0x21, writer.getDataBuffer()));
  }

  private byte[] create(String type, byte[] data) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    writer.text("type".getBytes());
    writer.text(type.getBytes(StandardCharsets.US_ASCII));
    writer.text("data".getBytes());
    writer.bytes(data);
    return field(transmit(0x34, writer.getDataBuffer()), "index");
  }

  private byte[] itemRequest(byte[] index) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 1);
    writer.text("index".getBytes());
    writer.bytes(index);
    return writer.getDataBuffer();
  }

  private byte[] keyRequest(byte[] index, String type, byte[] context, String cipher) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (cipher == null ? 3 : 5));
    writeKey(writer, index, type);
    writeDerivation(writer, context);

    if (cipher != null) {
      writeSigning(writer, cipher);
    }

    return writer.getDataBuffer();
  }

  private void writeKey(CBORBufferWriter writer, byte[] index, String type) {
    writer.text("index".getBytes());
    writer.bytes(index);
    writer.text("type".getBytes());
    writer.text(type.getBytes(StandardCharsets.US_ASCII));
  }

  private void writeDerivation(CBORBufferWriter writer, byte[] context) {
    writer.text("derivation".getBytes());
    writer.map((short) 2);
    writer.text("type".getBytes());
    writer.text("monoid-001".getBytes());
    writer.text("context".getBytes());
    writer.bytes(context);
  }

  private void writeSigning(CBORBufferWriter writer, String cipher) {
    writer.text("cipher".getBytes());
    writer.text(cipher.getBytes(StandardCharsets.US_ASCII));
    writer.text((cipher.equals("ed25519") ? "message" : "digest").getBytes());
    writer.bytes(DIGEST);
  }

  private ResponseAPDU transmit(int instruction, byte[] request) {
    return simulator.transmitCommand(apdu(0, instruction, 0, 0, request));
  }

  private ResponseAPDU transmitFragments(int instruction, byte[] request, int chunkLength) {
    for (int offset = 0; offset < request.length; offset += chunkLength) {
      int end = Math.min(offset + chunkLength, request.length);
      boolean last = end == request.length;
      int cla = offset == 0 ? (last ? 0 : 0x90) : (last ? 0xA0 : 0xB0);
      ResponseAPDU response = simulator.transmitCommand(
        apdu(cla, instruction, 0, 0, Arrays.copyOfRange(request, offset, end))
      );

      if (last) {
        return response;
      }

      Assertions.assertEquals(0x9000, response.getSW());
      Assertions.assertEquals(0, response.getData().length);
    }

    throw new IllegalArgumentException("Empty request");
  }

  private void assertPublicKey(ResponseAPDU response, byte[] expected) {
    Assertions.assertArrayEquals(expected, field(response, "publicKey"));
    CBORBufferReader reader = new CBORBufferReader(response.getData());
    Assertions.assertEquals(1, reader.map());
    Assertions.assertFalse(reader.key("chainCode".getBytes()));
  }

  private byte[] field(ResponseAPDU response, String name) {
    assertNoError(response);
    CBORBufferReader reader = new CBORBufferReader(response.getData());
    reader.map();
    return reader.requireKey(name.getBytes(StandardCharsets.US_ASCII)).bytes().clone();
  }

  private void assertNoError(ResponseAPDU response) {
    Assertions.assertEquals(0x9000, response.getSW());
    CBORBufferReader reader = new CBORBufferReader(response.getData());
    reader.map();

    if (reader.key("error".getBytes())) {
      reader.map();
      Assertions.fail(
        new String(reader.requireKey("code".getBytes()).text(), StandardCharsets.US_ASCII)
      );
    }
  }

  private void assertError(ResponseAPDU response, byte[] code) {
    Assertions.assertEquals(0x9000, response.getSW());
    CBORBufferReader reader = new CBORBufferReader(response.getData());
    reader.map();
    reader.requireKey("error".getBytes()).map();
    Assertions.assertArrayEquals(code, reader.requireKey("code".getBytes()).text());
  }
}
