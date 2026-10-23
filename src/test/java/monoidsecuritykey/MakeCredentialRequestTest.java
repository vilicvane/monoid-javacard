package monoidsecuritykey;

import static monoidsecuritykey.Constants.KEY_ALG;
import static monoidsecuritykey.Constants.KEY_DISPLAY_NAME;
import static monoidsecuritykey.Constants.KEY_ID;
import static monoidsecuritykey.Constants.KEY_NAME;
import static monoidsecuritykey.Constants.KEY_PUBLIC_KEY;
import static monoidsecuritykey.Constants.KEY_RK;
import static monoidsecuritykey.Constants.KEY_TYPE;
import static monoidsecuritykey.Constants.KEY_UP;
import static monoidsecuritykey.Constants.KEY_UV;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import javacard.framework.ISOException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import monoidlib.CBORMap;
import monoidlib.CBORReader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class MakeCredentialRequestTest {

  private static final byte[] PIN = "314159".getBytes(StandardCharsets.UTF_8);
  private static final byte[] HASH = new byte[32];
  private static final short[] FIELDS = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  private MakeCredentialRequest request;

  @BeforeEach
  public void initialize() {
    CardSimulator simulator = new CardSimulator();
    simulator.installApplet(
      AIDUtil.create("f06d6f6e6f69647c02"),
      ClientPINTest.ClientPINCommandApplet.class
    );
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create("f06d6f6e6f69647c02")));
    request = new MakeCredentialRequest();
  }

  @AfterEach
  public void dispose() {
    Command.dispose();
  }

  @Test
  public void reorderedFieldsMatchThePreviousParserIncludingUnknownNestedValues() {
    Random random = new Random(0x4312);
    for (int sample = 0; sample < 64; sample++) {
      MapValue payload = valid();
      payload.put(5, Arrays.asList(map("id", new byte[32], "type", "public-key")));
      payload.put(6, map("extension", Arrays.asList(map("nested", "\u7528\u6237"), true)));
      payload.put(7, map("rk", true, "uv", sample % 2 == 0, "unknown", map("x", 9)));
      payload.put(8, new byte[16]);
      payload.put(9, 1);
      payload.put(20, Arrays.asList(map("unknown", new byte[] { 1, 2 })));
      reorder(payload, random);
      byte[] data = encode(payload);
      request.read(reader(data));
      Legacy expected = legacy(data);
      Assertions.assertArrayEquals(expected.record, record(request.input, request.resident()));
      Assertions.assertArrayEquals(expected.hash, request.clientDataHash);
      Assertions.assertEquals(expected.resident, request.resident());
      Assertions.assertEquals(expected.uv, request.requestedUV());
      Assertions.assertArrayEquals(
        expected.offsets,
        new short[] {
          request.excludeOffset(),
          request.pinAuthOffset(),
          request.pinProtocolOffset(),
        }
      );
    }
  }

  @Test
  public void preservesOptionalNameTruncationIgnoredRPFieldsAndRequestReuse() {
    String name = String.join("", Collections.nCopies(63, "a")) + "\u7528z";
    MapValue payload = valid();
    payload.put(2, map("displayName", Arrays.asList(1, 2), "name", 42, "id", "example.invalid"));
    payload.put(3, map("displayName", "", "name", name, "id", new byte[] { 7 }));
    byte[] data = encode(payload);
    request.read(reader(data));
    Assertions.assertArrayEquals(legacy(data).record, record(request.input, request.resident()));
    Assertions.assertEquals(63, request.input.length(CredentialInput.USER_NAME));
    Assertions.assertEquals(0, request.input.length(CredentialInput.USER_DISPLAY_NAME));
    payload.put(3, map("id", new byte[] { 8 }));
    payload.remove(7);
    data = encode(payload);
    request.read(reader(data));
    Assertions.assertArrayEquals(legacy(data).record, record(request.input, request.resident()));
    Assertions.assertEquals(-1, request.input.length(CredentialInput.USER_NAME));
    Assertions.assertEquals(-1, request.input.length(CredentialInput.USER_DISPLAY_NAME));
    Assertions.assertFalse(request.resident());
    Assertions.assertEquals(0, request.pinAuthOffset());
    Assertions.assertEquals(0, request.excludeOffset());
  }

  @Test
  public void duplicateKnownFieldsAreRejectedAtEveryParsedLevel() {
    for (int key = 1; key <= 9; key++) {
      MapValue payload = valid();
      if (key >= 5 && key != 7) payload.put(key, key == 8 ? new byte[0] : 1);
      payload.entries.add(new Object[] { key, 0 });
      error(CTAP.INVALID_CBOR, payload);
    }
    MapValue payload = valid();
    payload.put(2, map("id", "example.invalid", "name", "a", "name", "b"));
    error(CTAP.INVALID_CBOR, payload);
    payload = valid();
    payload.put(3, map("id", new byte[] { 1 }, "displayName", "a", "displayName", "b"));
    error(CTAP.INVALID_CBOR, payload);
    payload = valid();
    payload.put(4, Arrays.asList(map("type", "public-key", "alg", -7, "alg", -7)));
    error(CTAP.INVALID_CBOR, payload);
    payload = valid();
    payload.put(7, map("rk", true, "rk", false));
    error(CTAP.INVALID_CBOR, payload);
  }

  @Test
  public void requiredTypesLengthsAlgorithmsAndOptionsStillReject() {
    for (int key = 1; key <= 4; key++) {
      MapValue payload = valid();
      payload.remove(key);
      error(CTAP.MISSING_PARAMETER, payload);
    }
    for (int key : new int[] { 2, 3 }) {
      MapValue payload = valid();
      payload.put(key, map("name", "missing"));
      error(CTAP.MISSING_PARAMETER, payload);
    }
    for (Object[] invalid : new Object[][] {
      { 1, new byte[31], CTAP.INVALID_LENGTH },
      { 2, map("id", ""), CTAP.INVALID_LENGTH },
      { 2, map("id", new byte[] { 1 }), CTAP.CBOR_UNEXPECTED_TYPE },
      { 3, map("id", new byte[65]), CTAP.INVALID_LENGTH },
      { 3, map("id", "wrong"), CTAP.CBOR_UNEXPECTED_TYPE },
      { 4, Collections.emptyList(), CTAP.UNSUPPORTED_ALGORITHM },
      { 4, Arrays.asList(map("type", "public-key", "alg", -8)), CTAP.UNSUPPORTED_ALGORITHM },
      { 4, Arrays.asList(map("type", "public-key")), CTAP.MISSING_PARAMETER },
      { 7, map("up", false), CTAP.INVALID_OPTION },
      { 7, map("rk", 1), CTAP.CBOR_UNEXPECTED_TYPE },
    }) {
      MapValue payload = valid();
      payload.put(invalid[0], invalid[1]);
      error((Short) invalid[2], payload);
    }
    MapValue payload = valid();
    payload.put(
      4,
      Arrays.asList(map("type", "other", "alg", -8), map("alg", -7, "type", "public-key"))
    );
    request.read(reader(encode(payload)));
  }

  @Test
  public void validatesCompleteUTF8CanonicalHeadersAndUnknownContent() {
    byte[] badName = new byte[66];
    Arrays.fill(badName, (byte) 'a');
    badName[64] = (byte) 0xc3;
    badName[65] = 0x28;
    MapValue payload = valid();
    payload.put(3, map("id", new byte[] { 1 }, "name", raw(text(badName))));
    error(CTAP.INVALID_CBOR, payload);
    payload = valid();
    payload.put(6, map("unknown", raw(new byte[] { 0x62, (byte) 0xed, (byte) 0xa0 })));
    error(CTAP.INVALID_CBOR, payload);
    payload = valid();
    payload.entries.add(new Object[] { raw(new byte[] { 0x18, 0x01 }), new byte[32] });
    error(CTAP.INVALID_CBOR, payload);
    payload = valid();
    payload.put(1, raw(concat(new byte[] { 0x59, 0, 32 }, new byte[32])));
    error(CTAP.INVALID_CBOR, payload);
    payload = valid();
    payload.put(6, raw(new byte[] { (byte) 0x9f, (byte) 0xff }));
    error(CTAP.INVALID_CBOR, payload);
    byte[] valid = encode(valid());
    error(CTAP.INVALID_LENGTH, concat(valid, new byte[] { 0 }));
  }

  @Test
  public void unknownDepthLimitMatchesTheOriginalTopLevelScan() {
    for (int scope = 0; scope < 4; scope++) {
      for (int arrays = 4; arrays <= 8; arrays++) {
        Object value = 0;
        for (int i = 0; i < arrays; i++) value = Arrays.asList(value);
        MapValue payload = valid();
        if (scope == 0) payload.put(6, value);
        if (scope == 1) payload.put(2, map("id", "example.invalid", "unknown", value));
        if (scope == 2) payload.put(
          4,
          Arrays.asList(map("alg", -7, "type", "public-key", "unknown", value))
        );
        if (scope == 3) payload.put(7, map("unknown", value));
        byte[] data = encode(payload);
        Assertions.assertEquals(
          status(() -> legacy(data)),
          status(() -> request.read(reader(data))),
          "scope=" + scope + " arrays=" + arrays
        );
      }
    }
  }

  @Test
  public void malformedRequestNeverConsumesTheTokenProofBudgetEvenWithPINFirst() throws Exception {
    Authenticator authenticator = Command.authenticator;
    ClientPINTest.Host host = new ClientPINTest.Host(authenticator.pin);
    host.setPIN(PIN);
    byte[] token = host.getToken(PIN);
    byte[] invalidProof = proof(token);
    invalidProof[0] ^= 1;
    List<byte[]> invalidRequests = new ArrayList<>();
    MapValue payload = valid();
    payload.entries.add(0, new Object[] { 8, invalidProof });
    payload.entries.add(1, new Object[] { 9, 1 });
    payload.put(6, raw(new byte[] { 0x62, (byte) 0xc3, 0x28 }));
    invalidRequests.add(encode(payload));
    payload.put(6, raw(new byte[] { (byte) 0x81 }));
    invalidRequests.add(encode(payload));
    payload.remove(6);
    invalidRequests.add(concat(encode(payload), new byte[] { 0 }));
    for (int repeat = 0; repeat < 3; repeat++) {
      for (byte[] data : invalidRequests) {
        short result = status(() -> new CommandMakeCredential().execute(reader(data), null));
        Assertions.assertTrue(result == CTAP.INVALID_CBOR || result == CTAP.INVALID_LENGTH);
      }
    }
    // Two bad proofs must still be allowed before the third blocks; success would reset the budget.
    payload = valid();
    payload.put(8, invalidProof);
    payload.put(9, 1);
    byte[] data = encode(payload);
    Assertions.assertEquals(CTAP.PIN_AUTH_INVALID, status(() -> verify(data)));
    Assertions.assertEquals(CTAP.PIN_AUTH_INVALID, status(() -> verify(data)));
    Assertions.assertEquals(CTAP.PIN_AUTH_BLOCKED, status(() -> verify(data)));
    Assertions.assertEquals(8, authenticator.pin.getRetries());
  }

  @Test
  public void deferredPINOffsetsPreserveAbsenceEmptyProtocolAndWrongLengthSemantics()
    throws Exception {
    MapValue payload = valid();
    payload.put(9, "ignored without auth");
    Assertions.assertFalse(verify(encode(payload)));
    payload.put(8, new byte[0]);
    errorPIN(CTAP.PIN_NOT_SET, payload);
    ClientPINTest.Host host = new ClientPINTest.Host(Command.authenticator.pin);
    host.setPIN(PIN);
    byte[] token = host.getToken(PIN);
    payload.remove(8);
    errorPIN(CTAP.PIN_REQUIRED, payload);
    payload.put(8, new byte[0]);
    errorPIN(CTAP.PIN_INVALID, payload);
    payload.put(8, proof(token));
    payload.remove(9);
    errorPIN(CTAP.MISSING_PARAMETER, payload);
    payload.put(9, 2);
    errorPIN(CTAP.PIN_AUTH_INVALID, payload);
    payload.put(9, raw(new byte[] { 0x1a, 0, 1, 0, 1 }));
    errorPIN(CTAP.PIN_AUTH_INVALID, payload);
    payload.put(9, 1);
    Assertions.assertTrue(verify(encode(payload)));
    int[] lengths = { 15, 17, 15 };
    for (int attempt = 0; attempt < lengths.length; attempt++) {
      payload.put(8, new byte[lengths[attempt]]);
      errorPIN(attempt == 2 ? CTAP.PIN_AUTH_BLOCKED : CTAP.PIN_AUTH_INVALID, payload);
    }
  }

  private boolean verify(byte[] data) {
    CBORReader reader = reader(data);
    request.read(reader);
    return Command.authenticator.verifyPIN(
      reader,
      request.pinAuthOffset(),
      request.pinProtocolOffset(),
      request.clientDataHash,
      true
    );
  }

  private void errorPIN(short expected, MapValue payload) {
    Assertions.assertEquals(expected, status(() -> verify(encode(payload))));
  }

  private void error(short expected, MapValue payload) {
    error(expected, encode(payload));
  }

  private void error(short expected, byte[] data) {
    Assertions.assertEquals(expected, status(() -> request.read(reader(data))));
  }

  private static short status(Runnable operation) {
    try {
      operation.run();
      return 0;
    } catch (ISOException exception) {
      return exception.getReason();
    }
  }

  private static CBORReader reader(byte[] data) {
    return new CBORReader(data, (short) 0, (short) data.length);
  }

  private static byte[] record(CredentialInput input, boolean resident) {
    Credential credential = Credential.create(
      new byte[32],
      new byte[32],
      input,
      resident,
      new byte[65],
      null
    );
    byte[] data = new byte[credential.getLength()];
    credential.read((short) 0, data, (short) 0, (short) data.length);
    return data;
  }

  /** The previous indexed parser, retained only as a valid-input/depth differential oracle. */
  private static Legacy legacy(byte[] data) {
    CBORReader reader = reader(data);
    CBORMap fields = reader.map(FIELDS);
    Command.assertEmpty(reader);
    byte[] hash = fields.requireKey((short) 1).bytes((short) 32);
    CredentialInput input = new CredentialInput();
    CBORMap entity = fields
      .requireKey((short) 2)
      .map(new Object[] { KEY_ID, KEY_NAME, KEY_DISPLAY_NAME });
    input.read(CredentialInput.RP_ID, entity.requireKey(KEY_ID));
    entity = fields.requireKey((short) 3).map(new Object[] { KEY_ID, KEY_NAME, KEY_DISPLAY_NAME });
    input.read(CredentialInput.USER_ID, entity.requireKey(KEY_ID));
    input.read(CredentialInput.USER_NAME, entity.key(KEY_NAME) ? reader : null);
    input.read(CredentialInput.USER_DISPLAY_NAME, entity.key(KEY_DISPLAY_NAME) ? reader : null);
    short count = fields.requireKey((short) 4).array();
    boolean supported = false;
    for (short index = 0; index < count; index++) {
      CBORMap parameter = reader.map(new Object[] { KEY_TYPE, KEY_ALG });
      short next = reader.getOffset();
      boolean publicKey = parameter.requireKey(KEY_TYPE).textMatches(KEY_PUBLIC_KEY);
      short algorithm = parameter.requireKey(KEY_ALG).integer();
      supported |= publicKey && algorithm == -7;
      reader.setOffset(next);
    }
    if (!supported) ISOException.throwIt(CTAP.UNSUPPORTED_ALGORITHM);
    boolean resident = false;
    boolean uv = false;
    if (fields.key((short) 7)) {
      CBORMap options = reader.map(new Object[] { KEY_RK, KEY_UV, KEY_UP });
      if (options.key(KEY_UP)) ISOException.throwIt(CTAP.INVALID_OPTION);
      resident = options.key(KEY_RK) && reader.bool();
      uv = options.key(KEY_UV) && reader.bool();
    }
    short[] offsets = new short[3];
    short[] keys = { 5, 8, 9 };
    for (int i = 0; i < keys.length; i++) offsets[i] = fields.key(keys[i]) ? reader.getOffset() : 0;
    return new Legacy(record(input, resident), hash, resident, uv, offsets);
  }

  private static final class Legacy {

    final byte[] record;
    final byte[] hash;
    final boolean resident;
    final boolean uv;
    final short[] offsets;

    Legacy(byte[] record, byte[] hash, boolean resident, boolean uv, short[] offsets) {
      this.record = record;
      this.hash = hash;
      this.resident = resident;
      this.uv = uv;
      this.offsets = offsets;
    }
  }

  private static MapValue valid() {
    return map(
      1,
      HASH,
      2,
      map("id", "example.invalid", "name", "Example"),
      3,
      map("id", new byte[] { 7 }, "name", "\u7528\u6237", "displayName", "User"),
      4,
      Arrays.asList(map("type", "public-key", "alg", -7)),
      7,
      map("rk", true)
    );
  }

  private static MapValue map(Object... entries) {
    return new MapValue(entries);
  }

  private static final class MapValue {

    final List<Object[]> entries = new ArrayList<>();

    MapValue(Object... entries) {
      for (int i = 0; i < entries.length; i += 2) this.entries.add(
        new Object[] { entries[i], entries[i + 1] }
      );
    }

    void remove(Object key) {
      entries.removeIf(entry -> entry[0].equals(key));
    }

    void put(Object key, Object value) {
      remove(key);
      entries.add(new Object[] { key, value });
    }
  }

  private static void reorder(Object value, Random random) {
    if (value instanceof MapValue) {
      MapValue map = (MapValue) value;
      Collections.shuffle(map.entries, random);
      for (Object[] entry : map.entries) reorder(entry[1], random);
    } else if (value instanceof List) {
      for (Object entry : (List<?>) value) reorder(entry, random);
    }
  }

  private static final class Raw {

    final byte[] data;

    Raw(byte[] data) {
      this.data = data;
    }
  }

  private static Raw raw(byte[] data) {
    return new Raw(data);
  }

  private static byte[] encode(Object value) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    encode(output, value);
    return output.toByteArray();
  }

  private static void encode(ByteArrayOutputStream output, Object value) {
    if (value instanceof Raw) {
      byte[] data = ((Raw) value).data;
      output.write(data, 0, data.length);
    } else if (value instanceof MapValue) {
      List<Object[]> entries = ((MapValue) value).entries;
      header(output, 5, entries.size());
      for (Object[] entry : entries) {
        encode(output, entry[0]);
        encode(output, entry[1]);
      }
    } else if (value instanceof List) {
      List<?> values = (List<?>) value;
      header(output, 4, values.size());
      for (Object entry : values) encode(output, entry);
    } else if (value instanceof byte[]) {
      byte[] bytes = (byte[]) value;
      header(output, 2, bytes.length);
      output.write(bytes, 0, bytes.length);
    } else if (value instanceof String) {
      byte[] bytes = ((String) value).getBytes(StandardCharsets.UTF_8);
      header(output, 3, bytes.length);
      output.write(bytes, 0, bytes.length);
    } else if (value instanceof Boolean) {
      output.write((Boolean) value ? 0xf5 : 0xf4);
    } else {
      int number = ((Number) value).intValue();
      header(output, number < 0 ? 1 : 0, number < 0 ? -1 - number : number);
    }
  }

  private static void header(ByteArrayOutputStream output, int type, int value) {
    if (value < 24) output.write((type << 5) | value);
    else if (value <= 255) {
      output.write((type << 5) | 24);
      output.write(value);
    } else {
      output.write((type << 5) | 25);
      output.write(value >> 8);
      output.write(value);
    }
  }

  private static byte[] text(byte[] bytes) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    header(output, 3, bytes.length);
    output.write(bytes, 0, bytes.length);
    return output.toByteArray();
  }

  private static byte[] concat(byte[] first, byte[] second) {
    byte[] result = Arrays.copyOf(first, first.length + second.length);
    System.arraycopy(second, 0, result, first.length, second.length);
    return result;
  }

  private static byte[] proof(byte[] token) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(token, "HmacSHA256"));
    return Arrays.copyOf(mac.doFinal(HASH), 16);
  }
}
