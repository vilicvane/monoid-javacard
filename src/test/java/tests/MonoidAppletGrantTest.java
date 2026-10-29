package tests;

import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.assertISOError;
import static tests.MonoidItemTransferTest.customIndex;
import static tests.MonoidItemTransferTest.fields;
import static tests.MonoidItemTransferTest.sequence;

import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javacard.framework.AID;
import javacard.framework.ISOException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoid.Command;
import monoidlib.CBOR;
import monoidlib.CBORBufferReader;
import monoidlib.CBORBufferWriter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

public class MonoidAppletGrantTest {

  private static final AID CLIENT_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_NAMESPACE}}7d01"
    "f06d6f6e6f69647d01"
  );
  private static final AID OTHER_CLIENT_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_NAMESPACE}}7d02"
    "f06d6f6e6f69647d02"
  );

  @Test
  public void grantCommandsRequireAccessAuthorizationAndAlsoAcceptSecretAuthorization() {
    try (Card card = new Card(true)) {
      AppletGrantClient client = installClient(card, CLIENT_AID);
      Map<String, Object> request = grant("types", types(0x1000, false));
      card.reset();

      for (int instruction : new int[] { 0x50, 0x51, 0x52 }) {
        assertError(
          transmit(card, instruction, instruction == 0x50 ? fields() : request),
          "UNAUTHORIZED"
        );
      }

      Assertions.assertEquals(0, client.hashCalls);

      for (boolean secret : new boolean[] { false, true }) {
        card.reset();
        card.authenticate(secret);
        assertEmptyResponse(success(card, 0x51, request));
        Assertions.assertEquals(1, grants(card).size());
        assertEmptyResponse(success(card, 0x52, grant()));
        Assertions.assertTrue(grants(card).isEmpty());
      }
    }
  }

  @Test
  public void blockedSecretPINDeniesGrantManagementEvenWithAccessAuthorization() {
    try (Card card = new Card(true)) {
      AppletGrantClient client = installClient(card, CLIENT_AID);
      Map<String, Object> request = grant("types", types(0x1000, false));
      card.authenticate(false);
      success(card, 0x51, request);

      for (int attempt = 0; attempt < 5; attempt++) {
        assertError(card.transmit(0x21, fields("pin", "000000", "secret", true)), "INVALID_PIN");
      }

      card.authenticate(false);

      for (int instruction : new int[] { 0x50, 0x51, 0x52 }) {
        assertError(
          transmit(card, instruction, instruction == 0x50 ? fields() : request),
          "SECRET_PIN_BLOCKED"
        );
      }

      Assertions.assertEquals(1, client.hashCalls);
    }
  }

  @Test
  public void requiresAnInstalledClientWithTheIdentityInterface() {
    try (Card card = new Card(true)) {
      card.authenticate(false);
      assertError(transmit(card, 0x51, grant()), "NOT_FOUND");

      AppletGrantClient client = installClient(card, CLIENT_AID);
      client.exposesIdentity = false;
      assertError(transmit(card, 0x51, grant()), "INVALID_PARAMETER");
      Assertions.assertEquals(0, client.hashCalls);

      card.simulator.installApplet(OTHER_CLIENT_AID, AppletGrantClient.WrongInterface.class);
      assertError(
        transmit(card, 0x51, fields("aid", AppletTest.aidBytes(OTHER_CLIENT_AID))),
        "INVALID_PARAMETER"
      );
      Assertions.assertTrue(grants(card).isEmpty());

      client.exposesIdentity = true;
      success(card, 0x51, grant());
      Assertions.assertEquals(1, grants(card).size());
    }
  }

  @Test
  public void takesTheHashFromTheClientInsteadOfTheRequest() throws Exception {
    try (Card card = new Card(true)) {
      AppletGrantClient client = installClient(card, CLIENT_AID);
      card.authenticate(false);
      success(card, 0x51, grant("tokenHash", new byte[32]));
      Map<String, Object> stored = grants(card).get(0);
      byte[] expected = MessageDigest.getInstance("SHA-256").digest(client.token);
      Assertions.assertArrayEquals(expected, (byte[]) stored.get("tokenHash"));
      Assertions.assertEquals(1, client.hashCalls);
      Assertions.assertFalse(stored.containsKey("token"));
      Assertions.assertEquals(
        0,
        card.success(0x30, fields()).reader().requireKey(bytes("items")).array()
      );

      card.reset();
      card.authenticate(false);
      assertValueEquals(stored, grants(card).get(0));
      Assertions.assertEquals(1, client.hashCalls);
    }
  }

  @Test
  public void keepsExactCustomTypesAndWritableFlags() {
    try (Card card = new Card(true)) {
      installClient(card, CLIENT_AID);
      card.authenticate(false);
      List<Object> permissions = types(
        0x1000,
        false,
        0x1001,
        true,
        0x7FFF,
        false,
        0x8000,
        true,
        0xF000,
        false,
        0xFFFE,
        true
      );
      success(card, 0x51, grant("types", permissions));
      assertValueEquals(permissions, grants(card).get(0).get("types"));
      Map<String, Object> original = grants(card).get(0);

      for (int invalid : new int[] { 0, 0x0200, 0x0FFF, 0xFFFF }) {
        assertError(
          transmit(card, 0x51, grant("types", types(invalid, true))),
          "INVALID_PARAMETER"
        );
        assertValueEquals(original, grants(card).get(0));
      }

      assertError(
        transmit(card, 0x51, grant("types", types(0x1000, false, 0x1000, true))),
        "INVALID_PARAMETER"
      );
      assertValueEquals(original, grants(card).get(0));
    }
  }

  @Test
  public void keysSeedAndTypesCanBeGrantedIndependentlyOrTogether() {
    try (Card card = new Card(true)) {
      installClient(card, CLIENT_AID);
      byte[] seedIndex = card.create("seed", null, null, sequence(64), true);
      byte[] scalar = new byte[32];
      scalar[31] = 1;
      byte[] k1Index = card.create("secp256k1", null, null, scalar, true);
      byte[] r1Index = card.create("secp256r1", null, null, scalar, true);
      byte[] edIndex = card.create("ed25519", null, null, sequence(32), true);
      List<Object> keys = Arrays.asList(
        key(k1Index, "secp256k1"),
        key(r1Index, "secp256r1"),
        key(edIndex, "ed25519"),
        derived(seedIndex, fields("type", "bip32", "path", new byte[] { 0, 0, 0, 1 })),
        derived(
          seedIndex,
          fields("type", "slip10", "curve", "ed25519", "path", new byte[] { (byte) 0x80, 0, 0, 1 })
        ),
        derived(seedIndex, fields("type", "monoid-001", "context", bytes("fixed key"))),
        derived(
          seedIndex,
          fields("type", "monoid-001", "curve", "secp256r1", "context", bytes("fixed key"))
        ),
        derived(
          seedIndex,
          fields("type", "monoid-001", "curve", "ed25519", "context", bytes("fixed key"))
        )
      );
      Map<String, Object> seed = fields("index", seedIndex, "domain", bytes("passkey"));
      List<Object> permissions = types(0xF001, true);
      card.authenticate(false);

      for (Map<String, Object> requested : Arrays.asList(
        grant("types", permissions),
        grant("keys", keys),
        grant("seed", seed),
        grant("types", permissions, "keys", keys, "seed", seed)
      )) {
        success(card, 0x51, requested);
        Map<String, Object> stored = grants(card).get(0);
        for (String field : new String[] { "types", "keys", "seed" }) {
          Assertions.assertEquals(requested.containsKey(field), stored.containsKey(field));
          if (requested.containsKey(field)) {
            assertValueEquals(requested.get(field), stored.get(field));
          }
        }
      }
    }
  }

  @Test
  public void monoid001CurvesSurviveResetAndRejectInvalidReplacements() {
    try (Card card = new Card(true)) {
      installClient(card, CLIENT_AID);
      byte[] seedIndex = card.create("seed", null, null, sequence(64), true);
      List<Object> keys = Arrays.asList(
        derived(seedIndex, fields("type", "monoid-001", "context", new byte[0])),
        derived(
          seedIndex,
          fields("type", "monoid-001", "curve", "secp256r1", "context", new byte[0])
        ),
        derived(seedIndex, fields("type", "monoid-001", "curve", "ed25519", "context", new byte[0]))
      );
      card.authenticate(false);
      success(card, 0x51, grant("keys", keys));

      card.reset();
      card.authenticate(false);
      Map<String, Object> original = grants(card).get(0);
      assertValueEquals(keys, original.get("keys"));

      for (Map<String, Object> invalid : Arrays.asList(
        fields("type", "monoid-001", "curve", "secp256k1", "context", new byte[0]),
        fields("type", "monoid-001", "curve", "unknown", "context", new byte[0]),
        fields(
          "type",
          "monoid-001",
          "curve",
          "ed25519",
          "path",
          new byte[0],
          "context",
          new byte[0]
        )
      )) {
        assertError(
          transmit(card, 0x51, grant("keys", Arrays.asList(derived(seedIndex, invalid)))),
          "INVALID_PARAMETER"
        );
        assertValueEquals(original, grants(card).get(0));
      }
    }
  }

  @Test
  public void replacementClearsOmittedPermissionsAndRemovalIsIdempotent() {
    try (Card card = new Card(true)) {
      installClient(card, CLIENT_AID);
      byte[] seedIndex = card.create("seed", null, null, sequence(64), true);
      card.authenticate(false);
      success(
        card,
        0x51,
        grant(
          "types",
          types(0x1001, true),
          "seed",
          fields("index", seedIndex, "domain", new byte[0])
        )
      );
      success(card, 0x51, grant());
      Map<String, Object> stored = grants(card).get(0);
      Assertions.assertFalse(stored.containsKey("types"));
      Assertions.assertFalse(stored.containsKey("keys"));
      Assertions.assertFalse(stored.containsKey("seed"));

      success(card, 0x51, grant("types", new ArrayList<>(), "keys", new ArrayList<>()));
      stored = grants(card).get(0);
      for (String field : new String[] { "types", "keys" }) {
        Assertions.assertTrue(
          !stored.containsKey(field) || ((List<?>) stored.get(field)).isEmpty()
        );
      }
      Assertions.assertFalse(stored.containsKey("seed"));

      assertEmptyResponse(success(card, 0x52, grant()));
      assertEmptyResponse(success(card, 0x52, grant()));
      Assertions.assertTrue(grants(card).isEmpty());
      card.success(0x31, fields("index", seedIndex));
    }
  }

  @Test
  public void invalidKeyAndSeedSourcesCannotReplaceAnExistingGrant() {
    try (Card card = new Card(true)) {
      installClient(card, CLIENT_AID);
      byte[] seedIndex = card.create("seed", null, null, sequence(64), true);
      byte[] shortSeed = card.create("seed", null, null, sequence(32), true);
      byte[] scalar = new byte[32];
      scalar[31] = 1;
      byte[] keyIndex = card.create("secp256r1", null, null, scalar, true);
      byte[] dataIndex = card.create(customIndex(701), null, null, sequence(64), false);
      card.authenticate(false);
      success(card, 0x51, grant("types", types(0x1000, false)));
      Map<String, Object> original = grants(card).get(0);

      List<Map<String, Object>> invalidKeys = Arrays.asList(
        key(keyIndex, "secp256k1"),
        key(dataIndex, "seed"),
        derived(keyIndex, fields("type", "monoid-001", "context", new byte[0])),
        derived(shortSeed, fields("type", "monoid-001", "context", new byte[0])),
        derived(seedIndex, fields("type", "bip32", "path", new byte[3])),
        derived(seedIndex, fields("type", "slip10", "curve", "ed25519", "path", new byte[4])),
        derived(seedIndex, fields("type", "slip10", "curve", "secp256r1", "path", new byte[0])),
        derived(seedIndex, fields("type", "unknown", "path", new byte[0]))
      );

      for (Map<String, Object> invalid : invalidKeys) {
        assertError(
          transmit(card, 0x51, grant("keys", Arrays.asList(invalid))),
          "INVALID_PARAMETER"
        );
        assertValueEquals(original, grants(card).get(0));
      }

      assertISOError(
        transmit(card, 0x51, grant("keys", Arrays.asList(key(seedIndex, "seed")))),
        0x6A80
      );
      assertValueEquals(original, grants(card).get(0));

      for (byte[] invalid : new byte[][] { shortSeed, keyIndex, dataIndex }) {
        assertError(
          transmit(card, 0x51, grant("seed", fields("index", invalid, "domain", new byte[0]))),
          "INVALID_PARAMETER"
        );
        assertValueEquals(original, grants(card).get(0));
      }

      card.success(0x35, fields("index", seedIndex));
      assertError(
        transmit(card, 0x51, grant("seed", fields("index", seedIndex, "domain", new byte[0]))),
        "NOT_FOUND"
      );
      assertError(
        transmit(
          card,
          0x51,
          grant(
            "keys",
            Arrays.asList(derived(seedIndex, fields("type", "bip32", "path", new byte[0])))
          )
        ),
        "NOT_FOUND"
      );
      assertValueEquals(original, grants(card).get(0));
    }
  }

  @Test
  public void callbackFailuresAndInvalidHashLengthsLeaveTheGrantUnchanged() {
    try (Card card = new Card(true)) {
      AppletGrantClient client = installClient(card, CLIENT_AID);
      card.authenticate(false);
      success(card, 0x51, grant("types", types(0x1000, false)));
      Map<String, Object> original = grants(card).get(0);

      client.onHash = () -> ISOException.throwIt((short) 0x6985);
      assertISOError(transmit(card, 0x51, grant("types", types(0x1001, true))), 0x6985);
      assertValueEquals(original, grants(card).get(0));
      client.onHash = null;

      for (short length : new short[] { 0, 31, 33 }) {
        client.resultLength = length;
        assertError(transmit(card, 0x51, grant("types", types(0x1001, true))), "INVALID_PARAMETER");
        assertValueEquals(original, grants(card).get(0));
      }

      client.resultLength = 32;
      success(card, 0x51, grant("types", types(0x1001, true)));
      assertValueEquals(types(0x1001, true), grants(card).get(0).get("types"));
    }
  }

  @Test
  public void accessAuthorizationIsRecheckedAfterTheClientCallback() throws Exception {
    try (Card card = new Card(true)) {
      AppletGrantClient client = installClient(card, CLIENT_AID);
      card.authenticate(false);
      success(card, 0x51, grant("types", types(0x1000, false)));
      Map<String, Object> original = grants(card).get(0);
      Field authField = Command.class.getDeclaredField("auth");
      authField.setAccessible(true);
      short[] auth = (short[]) authField.get(null);
      client.onHash = () -> Arrays.fill(auth, (short) 0);

      assertError(transmit(card, 0x51, grant("types", types(0x1001, true))), "UNAUTHORIZED");
      assertError(transmit(card, 0x50, fields()), "UNAUTHORIZED");
      client.onHash = null;
      card.authenticate(false);
      assertValueEquals(original, grants(card).get(0));
      success(card, 0x51, grant("types", types(0x1001, true)));
    }
  }

  @Test
  public void fullAIDsKeepIndependentGrantsAndClientReplacementHasANewHash() {
    try (Card card = new Card(true)) {
      installClient(card, CLIENT_AID);
      installClient(card, OTHER_CLIENT_AID);
      card.authenticate(false);
      success(card, 0x51, grant("types", types(0x1000, false)));
      Map<String, Object> other = fields(
        "aid",
        AppletTest.aidBytes(OTHER_CLIENT_AID),
        "types",
        types(0x1001, true)
      );
      success(card, 0x51, other);
      List<Map<String, Object>> initial = grants(card);
      Assertions.assertEquals(2, initial.size());
      byte[] oldHash = (byte[]) findGrant(initial, CLIENT_AID).get("tokenHash");

      card.simulator.deleteApplet(CLIENT_AID);
      card.simulator.createApplet(CLIENT_AID, new byte[0], (short) 0, (byte) 0);
      Assertions.assertArrayEquals(
        oldHash,
        (byte[]) findGrant(grants(card), CLIENT_AID).get("tokenHash")
      );
      success(card, 0x51, grant());
      Assertions.assertFalse(
        Arrays.equals(oldHash, (byte[]) findGrant(grants(card), CLIENT_AID).get("tokenHash"))
      );
      assertValueEquals(
        findGrant(initial, OTHER_CLIENT_AID),
        findGrant(grants(card), OTHER_CLIENT_AID)
      );

      success(card, 0x52, grant());
      Assertions.assertEquals(1, grants(card).size());
      assertValueEquals(findGrant(initial, OTHER_CLIENT_AID), grants(card).get(0));
    }
  }

  @Test
  public void factoryResetClearsGrantsAlongWithItemsAndPINs() {
    try (Card card = new Card(true)) {
      installClient(card, CLIENT_AID);
      card.create(customIndex(702), null, null, new byte[] { 1 }, false);
      card.authenticate(false);
      success(card, 0x51, grant("types", types(0x1000, true)));
      card.reset();
      assertEmptyResponse(card.success(0xFF, fields()));
      assertError(transmit(card, 0x50, fields()), "UNAUTHORIZED");
      card.success(0x22, fields("pin", "888888", "secret", true));
      card.authenticate(true);
      Assertions.assertTrue(grants(card).isEmpty());
      Assertions.assertEquals(
        0,
        card.success(0x30, fields()).reader().requireKey(bytes("items")).array()
      );
      success(card, 0x51, grant());
      Assertions.assertEquals(1, grants(card).size());
    }
  }

  private static AppletGrantClient installClient(Card card, AID aid) {
    card.simulator.installApplet(aid, AppletGrantClient.class);
    return AppletGrantClient.installed;
  }

  private static Map<String, Object> grant(Object... entries) {
    Map<String, Object> request = fields("aid", AppletTest.aidBytes(CLIENT_AID));
    request.putAll(fields(entries));
    return request;
  }

  private static Map<String, Object> key(byte[] index, String type) {
    return fields("index", index, "type", type);
  }

  private static Map<String, Object> derived(byte[] index, Map<String, Object> derivation) {
    return fields("index", index, "type", "seed", "derivation", derivation);
  }

  private static List<Object> types(Object... entries) {
    List<Object> types = new ArrayList<>();
    for (int index = 0; index < entries.length; index += 2) {
      types.add(Arrays.asList(((Number) entries[index]).shortValue(), entries[index + 1]));
    }
    return types;
  }

  private static Map<String, Object> findGrant(List<Map<String, Object>> grants, AID aid) {
    for (Map<String, Object> grant : grants) {
      if (Arrays.equals(AppletTest.aidBytes(aid), (byte[]) grant.get("aid"))) {
        return grant;
      }
    }
    throw new AssertionError("Missing client grant");
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> grants(Card card) {
    Map<String, Object> result = (Map<String, Object>) read(
      new CBORBufferReader(success(card, 0x50, fields()).data)
    );
    return (List<Map<String, Object>>) result.get("grants");
  }

  private static void assertEmptyResponse(Result response) {
    Assertions.assertEquals(0, response.size());
  }

  static Result success(Card card, int instruction, Map<String, Object> request) {
    Result result = transmit(card, instruction, request);
    result.assertSuccess();
    return result;
  }

  private static Result transmit(Card card, int instruction, Map<String, Object> request) {
    CBORBufferWriter writer = new CBORBufferWriter();
    write(writer, request);
    byte[] data = writer.getDataBuffer().clone();
    ResponseAPDU response = null;
    int requestFrames = 0;
    for (int offset = 0; offset < data.length; offset += 255) {
      int end = Math.min(data.length, offset + 255);
      boolean last = end == data.length;
      int cla = offset == 0 ? (last ? 0 : 0x90) : (last ? 0xA0 : 0xB0);
      response = card.simulator.transmitCommand(
        new CommandAPDU(cla, instruction, 0, 0, Arrays.copyOfRange(data, offset, end))
      );
      requestFrames++;
      if (!last) {
        Assertions.assertEquals(0x9000, response.getSW());
      }
    }

    ByteArrayOutputStream output = new ByteArrayOutputStream();
    int responseFrames = 0;
    while (true) {
      output.write(response.getData(), 0, response.getData().length);
      responseFrames++;
      if (response.getSW1() != 0x61) {
        return new Result(output.toByteArray(), response.getSW(), requestFrames, responseFrames);
      }
      response = card.simulator.transmitCommand(
        new CommandAPDU(0, 0xC0, 0, 0, response.getSW2() == 0 ? 256 : response.getSW2())
      );
    }
  }

  private static void write(CBORBufferWriter writer, Object value) {
    if (value instanceof Map) {
      Map<?, ?> map = (Map<?, ?>) value;
      writer.map((short) map.size());
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        writer.text(bytes((String) entry.getKey()));
        write(writer, entry.getValue());
      }
    } else if (value instanceof List) {
      List<?> list = (List<?>) value;
      writer.array((short) list.size());
      for (Object entry : list) {
        write(writer, entry);
      }
    } else if (value instanceof byte[]) {
      writer.bytes((byte[]) value);
    } else if (value instanceof String) {
      writer.text(bytes((String) value));
    } else if (value instanceof Boolean) {
      writer.bool((Boolean) value);
    } else {
      writer.integer(((Number) value).shortValue());
    }
  }

  private static Object read(CBORBufferReader reader) {
    if (reader.is(CBOR.TYPE_MAP)) {
      int length = reader.map();
      Map<String, Object> result = new LinkedHashMap<>();
      for (int index = 0; index < length; index++) {
        result.put(new String(readBytes(reader, true), StandardCharsets.UTF_8), read(reader));
      }
      return result;
    }
    if (reader.is(CBOR.TYPE_ARRAY)) {
      int length = reader.array();
      List<Object> result = new ArrayList<>();
      for (int index = 0; index < length; index++) {
        result.add(read(reader));
      }
      return result;
    }
    if (reader.is(CBOR.TYPE_BYTES)) {
      return readBytes(reader, false);
    }
    if (reader.is(CBOR.TYPE_TEXT)) {
      return new String(readBytes(reader, true), StandardCharsets.UTF_8);
    }
    if (reader.is(CBOR.TYPE_SIMPLE_FLOAT)) {
      return reader.bool();
    }
    return reader.integer();
  }

  private static byte[] readBytes(CBORBufferReader reader, boolean text) {
    byte[] buffer = new byte[reader.getChunkLength(reader.getOffset())];
    short length = text ? reader.text(buffer) : reader.bytes(buffer);
    return Arrays.copyOf(buffer, length);
  }

  private static void assertValueEquals(Object expected, Object actual) {
    if (expected instanceof byte[]) {
      Assertions.assertArrayEquals((byte[]) expected, (byte[]) actual);
    } else if (expected instanceof Map) {
      Map<?, ?> expectedMap = (Map<?, ?>) expected;
      Map<?, ?> actualMap = (Map<?, ?>) actual;
      Assertions.assertEquals(expectedMap.keySet(), actualMap.keySet());
      for (Object key : expectedMap.keySet()) {
        assertValueEquals(expectedMap.get(key), actualMap.get(key));
      }
    } else if (expected instanceof List) {
      List<?> expectedList = (List<?>) expected;
      List<?> actualList = (List<?>) actual;
      Assertions.assertEquals(expectedList.size(), actualList.size());
      for (int index = 0; index < expectedList.size(); index++) {
        assertValueEquals(expectedList.get(index), actualList.get(index));
      }
    } else {
      Assertions.assertEquals(expected, actual);
    }
  }

  private static byte[] bytes(String text) {
    return text.getBytes(StandardCharsets.UTF_8);
  }
}
