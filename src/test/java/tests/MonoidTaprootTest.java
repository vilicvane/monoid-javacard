package tests;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.utils.AIDUtil;
import cz.muni.fi.crocs.rcard.client.CardType;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javacard.framework.AID;
import javax.smartcardio.ResponseAPDU;
import monoid.CurveException;
import monoid.MonoidApplet;
import monoid.MonoidException;
import monoididentity.MonoidIdentityApplet;
import monoidlib.CBORBufferReader;
import monoidlib.CBORBufferWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class MonoidTaprootTest extends AppletTest {

  private static final AID MONOID_IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_IDENTITY_AID}}"
    "f06d6f6e6f69640001"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );

  private static final byte[] PIN = "888888".getBytes(StandardCharsets.US_ASCII);

  // BIP86 test mnemonic: abandon (eleven times), about; no passphrase.
  private static final byte[] SEED = Hex.decode(
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
  );
  private static final byte[] DIGEST = Hex.decode(
    "43ddcab065bcc7bd8d80c479ed29d3658ccf3ac3343b7044013008bde5ca19cf"
  );
  private static final byte[] MERKLE_ROOT = Hex.decode(
    "8239b780abdeeafd9033083975fd7950a69f4e60942adabb99ee0c7e8c746da2"
  );

  public MonoidTaprootTest() {
    super(MONOID_AID, CardType.JCARDSIMLOCAL);
  }

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.bouncycastle.rsa.allow_unsafe_mod", "true");
    resetAppletState();

    simulator.installApplet(MONOID_IDENTITY_AID, MonoidIdentityApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));

    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    writer.text("pin".getBytes());
    writer.text(PIN);
    writer.text("secret".getBytes());
    writer.bool(true);
    assertNoError(transmit(0x22, writer.getDataBuffer()));
    authenticate();
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(MONOID_AID);
    simulator.deleteApplet(MONOID_IDENTITY_AID);
    resetAppletState();
  }

  private void resetAppletState() {
    // Separate simulator instances share Java static fields within the test JVM.
    MonoidApplet.safe = null;
    MonoidApplet.keystore = null;
  }

  @Test
  public void bip86SeedItems() throws Exception {
    byte[] seedIndex = create("seed", SEED);

    for (String[] vector : readVectors()) {
      byte[] path = Hex.decode(vector[1]);
      byte[] compressedKey = Hex.decode(vector[3]);
      byte[] outputKey = Hex.decode(vector[4]);
      byte[] chainCode = Hex.decode(vector[6]);

      ResponseAPDU response = transmit(0x40, keyRequest(seedIndex, path, null, null, null));
      Assertions.assertArrayEquals(compressedKey, field(response, "publicKey"), vector[0]);
      Assertions.assertArrayEquals(chainCode, field(response, "chainCode"), vector[0]);

      response = transmit(0x40, keyRequest(seedIndex, path, null, null, new byte[0]));
      Assertions.assertArrayEquals(outputKey, field(response, "publicKey"), vector[0]);
      Assertions.assertArrayEquals(chainCode, field(response, "chainCode"), vector[0]);

      requireSignature(
        transmit(0x41, keyRequest(seedIndex, path, "bip340", DIGEST, new byte[0])),
        DIGEST,
        outputKey
      );
      requireSignature(
        transmit(0x41, keyRequest(seedIndex, path, "bip340", DIGEST, null)),
        DIGEST,
        Arrays.copyOfRange(compressedKey, 1, 33)
      );
    }
  }

  @Test
  public void directItemsAndMerkleRootCommitments() throws Exception {
    for (String[] vector : readVectors()) {
      byte[] index = create("secp256k1", Hex.decode(vector[2]));
      byte[] compressedKey = Hex.decode(vector[3]);
      byte[] outputKey = Hex.decode(vector[4]);
      byte[] treeOutputKey = Hex.decode(vector[5]);

      ResponseAPDU response = transmit(0x40, keyRequest(index, null, null, null, null));
      Assertions.assertArrayEquals(compressedKey, field(response, "publicKey"));
      CBORBufferReader reader = new CBORBufferReader(response.getData());
      Assertions.assertEquals(1, reader.map());
      Assertions.assertFalse(reader.key("chainCode".getBytes()));

      for (byte[] root : new byte[][] { new byte[0], MERKLE_ROOT }) {
        byte[] expected = root.length == 0 ? outputKey : treeOutputKey;
        response = transmit(0x40, keyRequest(index, null, null, null, root));
        Assertions.assertArrayEquals(expected, field(response, "publicKey"));

        byte[] signature = requireSignature(
          transmit(0x41, keyRequest(index, null, "bip340", DIGEST, root)),
          DIGEST,
          expected
        );
        assertVerification(signature, DIGEST, root.length == 0 ? treeOutputKey : outputKey, false);
        assertVerification(signature, DIGEST, Arrays.copyOfRange(compressedKey, 1, 33), false);
      }

      requireSignature(
        transmit(0x41, keyRequest(index, null, "bip340", DIGEST, null)),
        DIGEST,
        Arrays.copyOfRange(compressedKey, 1, 33)
      );
    }
  }

  @Test
  public void merkleRootPreservesDerivedChainCode() throws Exception {
    String[] vector = readVectors().get(0);
    byte[] index = create("seed", SEED);
    byte[] path = Hex.decode(vector[1]);
    byte[] outputKey = Hex.decode(vector[5]);

    ResponseAPDU response = transmit(0x40, keyRequest(index, path, null, null, MERKLE_ROOT));
    Assertions.assertArrayEquals(outputKey, field(response, "publicKey"));
    Assertions.assertArrayEquals(Hex.decode(vector[6]), field(response, "chainCode"));
    requireSignature(
      transmit(0x41, keyRequest(index, path, "bip340", DIGEST, MERKLE_ROOT)),
      DIGEST,
      outputKey
    );
  }

  @Test
  public void booleanTaprootForDirectAndDerivedKeys() throws Exception {
    String[] vector = readVectors().get(0);
    byte[][] indices = { create("secp256k1", Hex.decode(vector[2])), create("seed", SEED) };

    for (int item = 0; item < indices.length; item++) {
      byte[] path = item == 0 ? null : Hex.decode(vector[1]);

      for (boolean taproot : new boolean[] { false, true }) {
        byte[] publicKey = Hex.decode(vector[taproot ? 4 : 3]);
        ResponseAPDU response = transmit(
          0x40,
          keyRequest(indices[item], path, null, null, taproot)
        );
        Assertions.assertArrayEquals(publicKey, field(response, "publicKey"));

        if (path != null) {
          Assertions.assertArrayEquals(Hex.decode(vector[6]), field(response, "chainCode"));
        }

        requireSignature(
          transmit(0x41, keyRequest(indices[item], path, "bip340", DIGEST, taproot)),
          DIGEST,
          taproot ? publicKey : Arrays.copyOfRange(publicKey, 1, 33)
        );
      }
    }
  }

  @Test
  public void rejectTaprootForOtherCiphers() throws Exception {
    String[] vector = readVectors().get(0);
    byte[] secpIndex = create("secp256k1", Hex.decode(vector[2]));
    byte[] edIndex = create("ed25519", new byte[32]);

    Assertions.assertArrayEquals(
      field(transmit(0x40, keyRequest(secpIndex, null, null, null, null)), "publicKey"),
      field(transmit(0x40, keyRequest(secpIndex, null, null, null, false)), "publicKey")
    );

    byte[] ecdsa = field(
      transmit(0x41, keyRequest(secpIndex, null, "ecdsa", DIGEST, null)),
      "signature"
    );
    Assertions.assertEquals(64, ecdsa.length);
    Process verification = new ProcessBuilder(
      "node",
      "scripts/verify-signature.js",
      Hex.toHexString(ecdsa),
      Hex.toHexString(DIGEST),
      vector[3]
    )
      .inheritIO()
      .start();
    Assertions.assertEquals(0, verification.waitFor());
    Assertions.assertEquals(
      64,
      field(transmit(0x41, keyRequest(edIndex, null, "ed25519", DIGEST, null)), "signature").length
    );

    for (boolean taproot : new boolean[] { false, true }) {
      assertError(
        transmit(0x41, keyRequest(secpIndex, null, "ecdsa", DIGEST, taproot)),
        MonoidException.CODE_INVALID_PARAMETER
      );

      for (String cipher : new String[] { null, "ed25519", "bip340" }) {
        assertError(
          transmit(
            cipher == null ? 0x40 : 0x41,
            keyRequest(edIndex, null, cipher, DIGEST, taproot)
          ),
          MonoidException.CODE_INVALID_PARAMETER
        );
      }
    }
  }

  @Test
  public void repeatedSignaturesAndReset() throws Exception {
    String[] vector = readVectors().get(0);
    byte[] index = create("secp256k1", Hex.decode(vector[2]));
    byte[] publicKey = Hex.decode(vector[4]);
    byte[] request = keyRequest(index, null, "bip340", DIGEST, new byte[0]);
    byte[] first = requireSignature(transmit(0x41, request), DIGEST, publicKey);
    byte[] second = requireSignature(transmit(0x41, request), DIGEST, publicKey);
    Assertions.assertFalse(
      Arrays.equals(first, second),
      "Fresh auxiliary randomness per signature"
    );

    simulator.reset();
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));

    // Rebuild transient request buffers after reset, just as a new host command would.
    request = keyRequest(index, null, "bip340", DIGEST, new byte[0]);
    assertError(transmit(0x41, request), MonoidException.CODE_UNAUTHORIZED);
    assertError(
      transmit(0x40, keyRequest(index, null, null, null, new byte[0])),
      MonoidException.CODE_UNAUTHORIZED
    );

    authenticate();
    requireSignature(transmit(0x41, request), DIGEST, publicKey);
  }

  @Test
  public void fragmentedRequestsWithTaprootBeforeKeyFields() throws Exception {
    String[] vector = readVectors().get(0);
    byte[] index = create("seed", SEED);
    byte[] path = Hex.decode(vector[1]);

    for (Object taproot : new Object[] { MERKLE_ROOT, false, true }) {
      byte[] outputKey = Hex.decode(
        vector[taproot == Boolean.FALSE ? 3 : taproot == Boolean.TRUE ? 4 : 5]
      );

      for (int instruction : new int[] { 0x40, 0x41 }) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map((short) (instruction == 0x40 ? 5 : 7));
        writeTaproot(writer, taproot);
        writer.text("padding".getBytes());
        writer.bytes(new byte[600]);

        if (instruction == 0x41) {
          writer.text("digest".getBytes());
          writer.bytes(DIGEST);
          writer.text("cipher".getBytes());
          writer.text("bip340".getBytes());
        }

        writer.text("derivation".getBytes());
        writer.map((short) 2);
        writer.text("path".getBytes());
        writer.bytes(path);
        writer.text("type".getBytes());
        writer.text("bip32".getBytes());
        writer.text("type".getBytes());
        writer.text("seed".getBytes());
        writer.text("index".getBytes());
        writer.bytes(index);

        ResponseAPDU response = transmitFragments(instruction, writer.getDataBuffer(), 73);

        if (instruction == 0x40) {
          Assertions.assertArrayEquals(outputKey, field(response, "publicKey"));
          Assertions.assertArrayEquals(Hex.decode(vector[6]), field(response, "chainCode"));
        } else {
          requireSignature(
            response,
            DIGEST,
            taproot == Boolean.FALSE ? Arrays.copyOfRange(outputKey, 1, 33) : outputKey
          );
        }
      }
    }
  }

  @Test
  public void invalidDigestsAndTaprootParametersRecover() throws Exception {
    String[] vector = readVectors().get(0);
    byte[] index = create("secp256k1", Hex.decode(vector[2]));

    for (int length : new int[] { 0, 31, 33, 64 }) {
      Assertions.assertEquals(
        0x6A80,
        transmit(0x41, keyRequest(index, null, "bip340", new byte[length], null)).getSW()
      );
    }

    for (int instruction : new int[] { 0x40, 0x41 }) {
      for (int length : new int[] { 1, 31, 33 }) {
        Assertions.assertEquals(
          0x6A80,
          transmit(
            instruction,
            keyRequest(index, null, instruction == 0x41 ? "bip340" : null, DIGEST, new byte[length])
          ).getSW()
        );
      }

      for (boolean rootType : new boolean[] { false, true }) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map((short) (instruction == 0x41 ? 5 : 3));
        writer.text("index".getBytes());
        writer.bytes(index);
        writer.text("type".getBytes());
        writer.text("secp256k1".getBytes());
        writer.text("taproot".getBytes());

        if (rootType) {
          writer.map((short) 1);
          writer.text("merkleRoot".getBytes());
          writer.text(new byte[32]);
        } else {
          writer.text("true".getBytes());
        }

        if (instruction == 0x41) {
          writer.text("cipher".getBytes());
          writer.text("bip340".getBytes());
          writer.text("digest".getBytes());
          writer.bytes(DIGEST);
        }

        Assertions.assertEquals(0x6A80, transmit(instruction, writer.getDataBuffer()).getSW());
      }

      for (int type : new int[] { 0xF6, 0xF7, 0x00, 0x40, 0x60, 0x80 }) {
        byte[] request = keyRequest(
          index,
          null,
          instruction == 0x41 ? "bip340" : null,
          DIGEST,
          false
        );
        request[request.length - 1] = (byte) type;
        Assertions.assertEquals(0x6A80, transmit(instruction, request).getSW());
      }
    }

    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 4);
    writer.text("index".getBytes());
    writer.bytes(index);
    writer.text("type".getBytes());
    writer.text("secp256k1".getBytes());
    writer.text("cipher".getBytes());
    writer.text("bip340".getBytes());
    writer.text("digest".getBytes());
    writer.text(DIGEST);
    Assertions.assertEquals(0x6A80, transmit(0x41, writer.getDataBuffer()).getSW());

    requireSignature(
      transmit(0x41, keyRequest(index, null, "bip340", DIGEST, new byte[0])),
      DIGEST,
      Hex.decode(vector[4])
    );
  }

  @Test
  public void incompatibleItemsAndCiphers() throws Exception {
    String[] vector = readVectors().get(0);
    byte[] secpIndex = create("secp256k1", Hex.decode(vector[2]));
    byte[] edIndex = create("ed25519", new byte[32]);
    byte[] seedIndex = create("seed", SEED);

    assertError(
      transmit(0x41, keyRequest(secpIndex, null, "ecdsa", DIGEST, new byte[0])),
      MonoidException.CODE_INVALID_PARAMETER
    );

    for (Object root : new Object[] { null, false, new byte[0], MERKLE_ROOT }) {
      assertError(
        transmit(0x41, keyRequest(edIndex, null, "bip340", DIGEST, root)),
        MonoidException.CODE_INVALID_PARAMETER
      );
    }

    for (String cipher : new String[] { null, "ed25519", "bip340" }) {
      assertError(
        transmit(
          cipher == null ? 0x40 : 0x41,
          keyRequest(edIndex, null, cipher, DIGEST, new byte[0])
        ),
        MonoidException.CODE_INVALID_PARAMETER
      );
    }

    for (int instruction : new int[] { 0x40, 0x41 }) {
      CBORBufferWriter writer = new CBORBufferWriter();
      writer.map((short) (instruction == 0x40 ? 4 : 6));
      writer.text("index".getBytes());
      writer.bytes(seedIndex);
      writer.text("type".getBytes());
      writer.text("seed".getBytes());
      writer.text("derivation".getBytes());
      writer.map((short) 3);
      writer.text("type".getBytes());
      writer.text("slip10".getBytes());
      writer.text("curve".getBytes());
      writer.text("ed25519".getBytes());
      writer.text("path".getBytes());
      writer.bytes(Hex.decode("8000002c800001f58000000080000000"));
      writeTaproot(writer, new byte[0]);

      if (instruction == 0x41) {
        writer.text("cipher".getBytes());
        writer.text("bip340".getBytes());
        writer.text("digest".getBytes());
        writer.bytes(DIGEST);
      }

      assertError(
        transmit(instruction, writer.getDataBuffer()),
        instruction == 0x41
          ? CurveException.CODE_UNSUPPORTED_CURVE
          : MonoidException.CODE_INVALID_PARAMETER
      );
    }

    requireSignature(
      transmit(0x41, keyRequest(secpIndex, null, "bip340", DIGEST, null)),
      DIGEST,
      Arrays.copyOfRange(Hex.decode(vector[3]), 1, 33)
    );
  }

  @Test
  public void declaredTypesMustMatchStoredItems() throws Exception {
    String[] vector = readVectors().get(0);
    byte[][] indices = {
      create("seed", SEED),
      create("secp256k1", Hex.decode(vector[2])),
      create("secp256r1", Hex.decode(vector[2])),
      create("ed25519", new byte[32]),
    };
    String[] mismatchedTypes = { "secp256k1", "secp256r1", "secp256k1", "secp256k1" };

    for (int item = 0; item < indices.length; item++) {
      for (String type : new String[] { null, mismatchedTypes[item], "unknown" }) {
        for (int instruction : new int[] { 0x40, 0x41 }) {
          CBORBufferWriter writer = new CBORBufferWriter();
          writer.map((short) (1 + (type == null ? 0 : 1) + (instruction == 0x41 ? 2 : 0)));
          writer.text("index".getBytes());
          writer.bytes(indices[item]);

          if (type != null) {
            writer.text("type".getBytes());
            writer.text(type.getBytes());
          }

          if (instruction == 0x41) {
            writer.text("cipher".getBytes());
            writer.text("bip340".getBytes());
            writer.text("digest".getBytes());
            writer.bytes(DIGEST);
          }

          ResponseAPDU response = transmit(instruction, writer.getDataBuffer());

          if (type == null) {
            Assertions.assertEquals(0x6A80, response.getSW());
          } else {
            assertError(response, MonoidException.CODE_INVALID_PARAMETER);
          }
        }
      }
    }
  }

  @Test
  public void rejectInvalidDerivationAndLegacyFields() throws Exception {
    String[] vector = readVectors().get(0);
    byte[] seedIndex = create("seed", SEED);
    byte[] directIndex = create("secp256k1", Hex.decode(vector[2]));

    for (int instruction : new int[] { 0x40, 0x41 }) {
      for (String missing : new String[] { "derivation", "type", "path", "curve" }) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map(
          (short) (2 + (missing.equals("derivation") ? 0 : 1) + (instruction == 0x41 ? 2 : 0))
        );
        writer.text("index".getBytes());
        writer.bytes(seedIndex);
        writer.text("type".getBytes());
        writer.text("seed".getBytes());

        if (!missing.equals("derivation")) {
          writer.text("derivation".getBytes());
          writer.map((short) (missing.equals("curve") ? 2 : 1));

          if (!missing.equals("type")) {
            writer.text("type".getBytes());
            writer.text(missing.equals("curve") ? "slip10".getBytes() : "bip32".getBytes());
          }

          if (!missing.equals("path")) {
            writer.text("path".getBytes());
            writer.bytes(new byte[0]);
          }
        }

        if (instruction == 0x41) {
          writer.text("cipher".getBytes());
          writer.text("bip340".getBytes());
          writer.text("digest".getBytes());
          writer.bytes(DIGEST);
        }

        Assertions.assertEquals(0x6A80, transmit(instruction, writer.getDataBuffer()).getSW());
      }

      for (String[] derivation : new String[][] {
        { "bip32", "secp256k1" },
        { "slip10", "secp256r1" },
        { "unknown", null },
      }) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map((short) (instruction == 0x41 ? 5 : 3));
        writer.text("index".getBytes());
        writer.bytes(seedIndex);
        writer.text("type".getBytes());
        writer.text("seed".getBytes());
        writer.text("derivation".getBytes());
        writer.map((short) (derivation[1] == null ? 2 : 3));
        writer.text("type".getBytes());
        writer.text(derivation[0].getBytes());

        if (derivation[1] != null) {
          writer.text("curve".getBytes());
          writer.text(derivation[1].getBytes());
        }

        writer.text("path".getBytes());
        writer.bytes(new byte[0]);

        if (instruction == 0x41) {
          writer.text("cipher".getBytes());
          writer.text("bip340".getBytes());
          writer.text("digest".getBytes());
          writer.bytes(DIGEST);
        }

        assertError(
          transmit(instruction, writer.getDataBuffer()),
          MonoidException.CODE_INVALID_PARAMETER
        );
      }

      assertError(
        transmit(
          instruction,
          keyRequest(directIndex, new byte[0], instruction == 0x41 ? "bip340" : null, DIGEST, null)
        ),
        MonoidException.CODE_INVALID_PARAMETER
      );

      for (String legacyField : new String[] { "seed", "curve", "path" }) {
        CBORBufferWriter writer = new CBORBufferWriter();
        writer.map((short) (instruction == 0x41 ? 5 : 3));
        writer.text("index".getBytes());
        writer.bytes(directIndex);
        writer.text("type".getBytes());
        writer.text("secp256k1".getBytes());
        writer.text(legacyField.getBytes());

        if (legacyField.equals("path")) {
          writer.bytes(new byte[0]);
        } else {
          writer.text(
            legacyField.equals("seed") ? "Bitcoin seed".getBytes() : "secp256k1".getBytes()
          );
        }

        if (instruction == 0x41) {
          writer.text("cipher".getBytes());
          writer.text("bip340".getBytes());
          writer.text("digest".getBytes());
          writer.bytes(DIGEST);
        }

        assertError(
          transmit(instruction, writer.getDataBuffer()),
          MonoidException.CODE_INVALID_PARAMETER
        );
      }
    }
  }

  private void authenticate() {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 1);
    writer.text("pin".getBytes());
    writer.text(PIN);
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

  private byte[] keyRequest(
    byte[] index,
    byte[] path,
    String cipher,
    byte[] digest,
    Object taproot
  ) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map(
      (short) (2 + (path == null ? 0 : 1) + (cipher == null ? 0 : 2) + (taproot == null ? 0 : 1))
    );
    writer.text("index".getBytes());
    writer.bytes(index);

    writer.text("type".getBytes());
    writer.text((index[0] == 2 ? "seed" : index[0] == 3 ? "secp256k1" : "ed25519").getBytes());

    if (path != null) {
      writer.text("derivation".getBytes());
      writer.map((short) 2);
      writer.text("type".getBytes());
      writer.text("bip32".getBytes());
      writer.text("path".getBytes());
      writer.bytes(path);
    }

    if (cipher != null) {
      writer.text("cipher".getBytes());
      writer.text(cipher.getBytes(StandardCharsets.US_ASCII));
      writer.text((cipher.equals("ed25519") ? "message" : "digest").getBytes());
      writer.bytes(digest);
    }

    if (taproot != null) {
      writeTaproot(writer, taproot);
    }

    return writer.getDataBuffer();
  }

  private void writeTaproot(CBORBufferWriter writer, Object taproot) {
    writer.text("taproot".getBytes());

    if (taproot instanceof Boolean) {
      writer.bool((Boolean) taproot);
      return;
    }

    byte[] merkleRoot = (byte[]) taproot;
    writer.map((short) (merkleRoot.length == 0 ? 0 : 1));

    if (merkleRoot.length > 0) {
      writer.text("merkleRoot".getBytes());
      writer.bytes(merkleRoot);
    }
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

  private byte[] requireSignature(ResponseAPDU response, byte[] digest, byte[] publicKey)
    throws Exception {
    byte[] signature = field(response, "signature");
    Assertions.assertEquals(64, signature.length);
    assertVerification(signature, digest, publicKey, true);
    byte[] changed = digest.clone();
    changed[0] ^= 1;
    assertVerification(signature, changed, publicKey, false);
    return signature;
  }

  private void assertVerification(byte[] signature, byte[] digest, byte[] publicKey, boolean valid)
    throws Exception {
    Process process = new ProcessBuilder(
      "node",
      "scripts/verify-schnorr.js",
      Hex.toHexString(signature),
      Hex.toHexString(digest),
      Hex.toHexString(publicKey)
    )
      .inheritIO()
      .start();
    Assertions.assertEquals(valid ? 0 : 1, process.waitFor());
  }

  private List<String[]> readVectors() throws Exception {
    List<String[]> vectors = new ArrayList<>();

    try (
      BufferedReader reader = new BufferedReader(
        new InputStreamReader(
          getClass().getResourceAsStream("/taproot.tsv"),
          StandardCharsets.US_ASCII
        )
      );
    ) {
      String line;

      while ((line = reader.readLine()) != null) {
        if (!line.isEmpty() && !line.startsWith("#")) {
          vectors.add(line.split("\t"));
        }
      }
    }

    Assertions.assertEquals(3, vectors.size());
    return vectors;
  }
}
