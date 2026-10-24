package tests;

import static tests.MonoidClientFixture.*;
import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.fields;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoid.Monoid;
import monoidlib.CBORBufferReader;
import monoidlib.CBORBufferWriter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class MonoidHMACTest {

  private static final short TYPE = (short) 0xF120;

  @Test
  public void rfc2202And4231KnownAnswersUseSecretKeysWithoutReadPermission() {
    byte[] key = new byte[20];
    Arrays.fill(key, (byte) 0x0B);
    byte[] message = ascii("Hi There");
    String[] expected = {
      "b617318655057264e28bc0b6fb378c8ef146be00",
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
      "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" +
      "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    };

    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      byte[] index = fixture.card.create("hmac", null, null, key, true);
      fixture.grant(CLIENT, "keys", Arrays.asList(hmacKey(index)));

      Monoid session = fixture.connect();
      assertStatus(0x6982, () -> session.get(global(index)));

      for (byte algorithm = 1; algorithm <= 3; algorithm++) {
        Assertions.assertArrayEquals(
          hex(expected[algorithm - 1]),
          calculate(session, algorithm, index, message)
        );
      }
    }
  }

  @Test
  public void longKeysAndEmptyMessagesMatchIndependentHmac() throws Exception {
    int[] keyLengths = { 1, 63, 64, 65, 127, 128, 129, 131, 255 };
    int[] messageLengths = { 0, 8, 63, 64, 129, 257 };

    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      byte[][] keys = new byte[keyLengths.length][];
      byte[][] indices = new byte[keyLengths.length][];
      List<Map<String, Object>> grants = new ArrayList<>();

      for (int keyIndex = 0; keyIndex < keyLengths.length; keyIndex++) {
        keys[keyIndex] = sequence(keyLengths[keyIndex]);
        indices[keyIndex] = fixture.card.create("hmac", null, null, keys[keyIndex], true);
        grants.add(hmacKey(indices[keyIndex]));
      }

      fixture.grant(CLIENT, "keys", grants);
      Monoid session = fixture.connect();

      for (byte algorithm = 1; algorithm <= 3; algorithm++) {
        for (int keyIndex = 0; keyIndex < keys.length; keyIndex++) {
          for (int messageLength : messageLengths) {
            byte[] message = sequence(messageLength);
            Assertions.assertArrayEquals(
              expected(algorithm, keys[keyIndex], message),
              calculate(session, algorithm, indices[keyIndex], message)
            );
          }
        }
      }
    }
  }

  @Test
  public void hmacRequiresTheExactGrantedKeyAndDoesNotUseCustomItemData() {
    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      byte[] selected = fixture.card.create("hmac", null, null, new byte[] { 1 }, true);
      byte[] adjacent = fixture.card.create("hmac", null, null, new byte[] { 2 }, true);
      byte[] custom = fixture.card.create(index(TYPE, 1), null, null, new byte[] { 3 }, false);

      fixture.grant(CLIENT, "types", Arrays.asList(Arrays.asList(TYPE, true)));
      Monoid reader = fixture.connect();

      assertStatus(0x6982, () -> calculate(reader, Monoid.HMAC_SHA256, selected, new byte[0]));
      assertStatus(0x6982, () -> calculate(reader, Monoid.HMAC_SHA256, custom, new byte[0]));

      fixture.select(MONOID);
      fixture.card.authenticate(false);
      fixture.grant(CLIENT, "keys", Arrays.asList(hmacKey(selected)));

      CBORBufferReader response = fixture.card.success(0x50, fields()).reader();
      response.requireKey(ascii("grants"));
      Assertions.assertEquals(1, response.array());
      response.map();
      response.requireKey(ascii("keys"));
      Assertions.assertEquals(1, response.array());
      response.map();
      Assertions.assertArrayEquals(selected, response.requireKey(ascii("index")).bytes());
      Assertions.assertArrayEquals(ascii("hmac"), response.requireKey(ascii("type")).text());

      Monoid hmac = fixture.connect();

      Assertions.assertEquals(
        32,
        calculate(hmac, Monoid.HMAC_SHA256, selected, new byte[0]).length
      );
      assertStatus(0x6982, () -> calculate(hmac, Monoid.HMAC_SHA256, adjacent, new byte[0]));
      assertStatus(0x6982, () -> calculate(hmac, Monoid.HMAC_SHA256, custom, new byte[0]));
      assertStatus(0x6982, () -> calculate(reader, Monoid.HMAC_SHA256, selected, new byte[0]));

      fixture.select(MONOID);
      fixture.card.authenticate(false);
      fixture.card.success(0x52, fields("aid", AppletTest.aidBytes(CLIENT)));
      fixture.select(CLIENT);

      assertStatus(0x6982, () -> calculate(hmac, Monoid.HMAC_SHA256, selected, new byte[0]));
    }
  }

  @Test
  public void hmacGrantRejectsOtherKeyTypesAndDerivation() {
    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      byte[] hmac = fixture.card.create("hmac", null, null, sequence(32), true);
      byte[] scalar = new byte[32];
      scalar[31] = 1;
      byte[] ec = fixture.card.create("secp256r1", null, null, scalar, true);
      byte[] custom = fixture.card.create(index(TYPE, 1), null, null, sequence(32), false);

      fixture.grant(CLIENT, "keys", Arrays.asList(hmacKey(hmac)));

      assertInvalidGrant(fixture, hmacKey(ec));
      assertInvalidGrant(fixture, hmacKey(custom));
      assertInvalidGrant(fixture, fields("index", hmac, "type", "secp256r1"));
      assertInvalidGrant(
        fixture,
        fields(
          "index",
          hmac,
          "type",
          "hmac",
          "derivation",
          fields("type", "monoid-001", "context", new byte[0])
        )
      );

      Assertions.assertEquals(
        32,
        calculate(fixture.connect(), Monoid.HMAC_SHA256, hmac, new byte[0]).length
      );

      fixture.select(MONOID);
      fixture.card.authenticate(false);
      fixture.grant(CLIENT, "keys", Arrays.asList(fields("index", ec, "type", "secp256r1")));

      Monoid session = fixture.connect();
      assertStatus(0x6982, () -> calculate(session, Monoid.HMAC_SHA256, ec, new byte[0]));
      assertStatus(0x6982, () -> calculate(session, Monoid.HMAC_SHA256, hmac, new byte[0]));
    }
  }

  @Test
  public void rangedOverlappingInputsAreReadBeforeOutputAndFailuresDoNotWrite() throws Exception {
    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      byte[] key = sequence(131);
      byte[] selected = fixture.card.create("hmac", null, null, key, true);
      fixture.grant(CLIENT, "keys", Arrays.asList(hmacKey(selected)));

      Monoid session = fixture.connect();
      byte[] shared = global(new byte[100]);
      System.arraycopy(selected, 0, shared, 3, selected.length);

      byte[] message = sequence(23);
      System.arraycopy(message, 0, shared, 20, message.length);

      Assertions.assertEquals(
        64,
        session.hmac(
          Monoid.HMAC_SHA512,
          shared,
          (short) 3,
          shared,
          (short) 20,
          (short) 23,
          shared,
          (short) 0
        )
      );
      Assertions.assertArrayEquals(
        expected(Monoid.HMAC_SHA512, key, message),
        Arrays.copyOf(shared, 64)
      );

      byte[] id = global(selected);
      byte[] input = global(message);
      byte[] output = global(sequence(64));
      byte[] unchanged = output.clone();

      assertStatus(0x6A80, () ->
        session.hmac(
          (byte) 9,
          id,
          (short) 0,
          input,
          (short) 0,
          (short) input.length,
          output,
          (short) 0
        )
      );
      assertStatus(0x6A80, () ->
        session.hmac(
          Monoid.HMAC_SHA256,
          id,
          (short) 1,
          input,
          (short) 0,
          (short) input.length,
          output,
          (short) 0
        )
      );
      assertStatus(0x6A80, () ->
        session.hmac(
          Monoid.HMAC_SHA256,
          id,
          (short) 0,
          input,
          (short) 0,
          (short) -1,
          output,
          (short) 0
        )
      );
      assertStatus(0x6A80, () ->
        session.hmac(
          Monoid.HMAC_SHA512,
          id,
          (short) 0,
          input,
          (short) 0,
          (short) input.length,
          output,
          (short) 1
        )
      );
      Assertions.assertArrayEquals(unchanged, output);
      Assertions.assertEquals(32, calculate(session, Monoid.HMAC_SHA256, selected, message).length);
    }
  }

  @Test
  public void tokenCallerAndResetChecksProtectHmacWithoutImplicitUserConsumption() {
    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      byte[] selected = fixture.card.create("hmac", null, null, new byte[] { 1 }, true);
      fixture.grant(CLIENT, "keys", Arrays.asList(hmacKey(selected)));
      fixture.grant(OTHER);
      fixture.approve(CLIENT);

      Monoid session = fixture.connect(CLIENT, (byte) 0, false);
      assertStatus(0x6982, () -> calculate(session, Monoid.HMAC_SHA256, selected, new byte[0]));

      session.authenticate(global(fixture.client.token));
      calculate(session, Monoid.HMAC_SHA256, selected, new byte[0]);
      session.consumeUserAuthentication();
      calculate(session, Monoid.HMAC_SHA256, selected, new byte[0]);

      fixture.select(OTHER);
      assertStatus(0x6982, () -> calculate(session, Monoid.HMAC_SHA256, selected, new byte[0]));

      fixture.select(CLIENT);
      assertStatus(0x6982, () -> session.authenticate(global(new byte[32])));
      assertStatus(0x6982, () -> calculate(session, Monoid.HMAC_SHA256, selected, new byte[0]));

      session.authenticate(global(fixture.client.token));
      fixture.card.reset();
      fixture.select(CLIENT);

      assertStatus(0x6982, () -> session.authenticate(global(fixture.client.token)));
      assertStatus(0x6982, () -> calculate(session, Monoid.HMAC_SHA256, selected, new byte[0]));
      calculate(fixture.connect(), Monoid.HMAC_SHA256, selected, new byte[0]);
    }
  }

  private static byte[] calculate(Monoid session, byte algorithm, byte[] index, byte[] message) {
    byte[] output = global(new byte[64]);
    short length = session.hmac(
      algorithm,
      global(index),
      (short) 0,
      global(message),
      (short) 0,
      (short) message.length,
      output,
      (short) 0
    );

    return Arrays.copyOf(output, length);
  }

  private static Map<String, Object> hmacKey(byte[] index) {
    return fields("index", index, "type", "hmac");
  }

  private static void assertInvalidGrant(MonoidClientFixture fixture, Map<String, Object> key) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    writer.text(ascii("aid"));
    writer.bytes(AppletTest.aidBytes(CLIENT));
    writer.text(ascii("keys"));
    writer.array((short) 1);
    writeMap(writer, key);

    ResponseAPDU response = fixture.card.simulator.transmitCommand(
      new CommandAPDU(0, 0x51, 0, 0, writer.getDataBuffer().clone())
    );
    assertError(
      new MonoidItemTransferTest.Result(response.getData(), response.getSW(), 1, 1),
      "INVALID_PARAMETER"
    );
  }

  private static void writeMap(CBORBufferWriter writer, Map<String, Object> fields) {
    writer.map((short) fields.size());

    for (Map.Entry<String, Object> field : fields.entrySet()) {
      writer.text(ascii(field.getKey()));
      Object value = field.getValue();

      if (value instanceof byte[]) {
        writer.bytes((byte[]) value);
      } else if (value instanceof String) {
        writer.text(ascii((String) value));
      } else {
        @SuppressWarnings("unchecked")
        Map<String, Object> nested = (Map<String, Object>) value;
        writeMap(writer, nested);
      }
    }
  }

  private static byte[] expected(byte algorithm, byte[] key, byte[] message) throws Exception {
    String name = algorithm == Monoid.HMAC_SHA1
      ? "HmacSHA1"
      : algorithm == Monoid.HMAC_SHA256 ? "HmacSHA256" : "HmacSHA512";
    Mac mac = Mac.getInstance(name);
    mac.init(new SecretKeySpec(key, name));

    return mac.doFinal(message);
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] sequence(int length) {
    byte[] result = new byte[length];

    for (int index = 0; index < length; index++) {
      result[index] = (byte) (index * 7 + 3);
    }

    return result;
  }

  private static byte[] hex(String value) {
    byte[] result = new byte[value.length() / 2];

    for (int index = 0; index < result.length; index++) {
      result[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
    }

    return result;
  }
}
