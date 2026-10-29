package tests;

import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.fields;
import static tests.MonoidItemTransferTest.sequence;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoidlib.CBORBufferWriter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

public class Monoid001Ed25519Test {

  private static final byte[] SEED = sequence(64);
  private static final byte[] BINARY_CONTEXT = Hex.decode("00010200ff");
  private static final byte[] MESSAGE = Hex.decode("72");

  // Independently generated with Node crypto.hkdfSync('sha512', seed, 'Monoid-001',
  // 'Monoid-001' || 0x01 || context || 0x00, 32), then crypto.sign(null, message, key).
  private static final String[][] VECTORS = {
    {
      "3ca45f0809035fdfc7820573d8c3d0829939945aef1361517f0f44f4ecdeabc8",
      "3bac0815174a5af3eed1636eef4ff0b7f3fa225f952c40a64d84012449fb8273",
      "3e5a4292f07a942c439c39b4f746ee7b76019f1c7ae6e74bc53206356dcf2bae8" +
      "cd9ad8af93f98174c8acab8aeb6f94797ec2adf7b8fb590fad03288e8391806",
    },
    {
      "83e8916442da94f6b66e13836b0f065c60825eaf87955d876044e01fe1be9b39",
      "62e52cd8effc619db4a8daa340b5aa8f56d506e38710d2d5ee7b1ed1cf43ce89",
      "f859527363fe3ef4250f62a89dc60759aac1835e41a710b7b0ef7067c22d3ca5b9" +
      "692ac9c91bc55f239624d460a53016fedcff2553a2261115ed4858b88ad40e",
    },
    {
      "46e71fc0712bf325a54311381ec470c30c82dbf118f460c8680215177d492e2b",
      "b0a01d2cdadd7f1f5fd71d9c1ca065ae1ce09afdc4b997fda176c51295f2edd5",
      "45263ae7e418aa6feee1ecb0da5b2d106ad0b4871e453ef019a09126da85f080a" +
      "f49f603abe2b29fb55727bf7666a7080384e9ff03bbb16cab516f85b0c66804",
    },
    {
      "ec497c5e1084ed8211c22ba5424ed76f4631217ec3950cdaebd482bd49203339",
      "c85061879615281795ec2329902b33f7257d2d336ba188688b4ac99930a17bbf",
      "3c124fa4c1dd3008791ac440b12581dd7d16730b43bff01611f06a94f8e7ebe15" +
      "6b72e6f379003a9f7dc916b56aa19463d11306047c7bc5fa3d042c609c70f0d",
    },
  };

  @Test
  public void emptyAndBinaryContextsMatchIndependentEd25519Vectors() throws Exception {
    try (Card card = new Card(true)) {
      byte[] index = card.create("seed", null, null, SEED, true);
      byte[][] contexts = { new byte[0], BINARY_CONTEXT };
      byte[][] messages = { new byte[0], MESSAGE };

      for (int vector = 0; vector < contexts.length; vector++) {
        byte[] privateKey = derive(SEED, contexts[vector]);
        Assertions.assertArrayEquals(Hex.decode(VECTORS[vector][0]), privateKey);
        byte[] direct = card.create("ed25519", null, null, privateKey, true);

        assertVector(card, index, contexts[vector], messages[vector], vector);
        assertVector(card, index, contexts[vector], messages[vector], vector);

        Result publicKey = transmit(card, 0x40, fields("index", direct, "type", "ed25519"));
        publicKey.assertSuccess();
        Assertions.assertArrayEquals(Hex.decode(VECTORS[vector][1]), publicKey.bytes("publicKey"));

        Result signature = transmit(
          card,
          0x41,
          fields(
            "index",
            direct,
            "type",
            "ed25519",
            "cipher",
            "ed25519",
            "message",
            messages[vector]
          )
        );
        signature.assertSuccess();
        Assertions.assertArrayEquals(Hex.decode(VECTORS[vector][2]), signature.bytes("signature"));
      }
    }
  }

  @Test
  public void p256AndEd25519CacheEntriesStaySeparate() {
    try (Card card = new Card(true)) {
      byte[] index = card.create("seed", null, null, SEED, true);
      byte[] expected = Hex.decode(
        "027b09b64420ee4a22f3b8cd3bbe22c08b77c35003b105d8f050bb39b5bd947de9"
      );

      for (int round = 0; round < 2; round++) {
        for (String curve : new String[] { null, "secp256r1" }) {
          Map<String, Object> request = key(index, curve, BINARY_CONTEXT);
          Result result = transmit(card, 0x40, request);
          result.assertSuccess();
          Assertions.assertArrayEquals(expected, result.bytes("publicKey"));

          assertVector(card, index, BINARY_CONTEXT, MESSAGE, 1);
        }
      }
    }
  }

  @Test
  public void fragmentedMessagesAndReorderedFieldsUseTheCompleteContext() throws Exception {
    try (Card card = new Card(true)) {
      byte[] index = card.create("seed", null, null, SEED, true);
      byte[] context = sequence(96);
      byte[] message = sequence(600);
      Assertions.assertArrayEquals(Hex.decode(VECTORS[2][0]), derive(SEED, context));

      for (boolean messageFirst : new boolean[] { false, true }) {
        Map<String, Object> request = fields();

        if (messageFirst) {
          request.put("message", message);
        }

        request.put(
          "derivation",
          fields("context", context, "curve", "ed25519", "type", "monoid-001")
        );
        request.put("cipher", "ed25519");
        request.put("type", "seed");
        request.put("index", index);

        if (!messageFirst) {
          request.put("message", message);
        }

        Result result = transmit(card, 0x41, request, 37);
        result.assertSuccess();
        Assertions.assertTrue(result.requestFrames > 1);
        Assertions.assertArrayEquals(Hex.decode(VECTORS[2][2]), result.bytes("signature"));
      }

      assertVector(card, index, context, message, 2);
    }
  }

  @Test
  public void resetAndSourceChangesKeepAuthorizationAndCacheSemantics() throws Exception {
    try (Card card = new Card(true)) {
      byte[] index = card.create("seed", null, null, SEED, true);
      assertVector(card, index, BINARY_CONTEXT, MESSAGE, 1);
      card.reset();

      assertError(transmit(card, 0x40, key(index, "ed25519", BINARY_CONTEXT)), "UNAUTHORIZED");
      assertError(transmit(card, 0x41, signing(index, BINARY_CONTEXT, MESSAGE)), "UNAUTHORIZED");
      card.authenticate(false);
      assertVector(card, index, BINARY_CONTEXT, MESSAGE, 1);

      byte[] updated = SEED.clone();
      updated[63] ^= 1;
      Assertions.assertArrayEquals(Hex.decode(VECTORS[3][0]), derive(updated, BINARY_CONTEXT));
      card.authenticate(true);
      card.success(0x33, fields("index", index, "data", updated));
      card.authenticate(false);
      assertVector(card, index, BINARY_CONTEXT, MESSAGE, 3);

      card.authenticate(true);
      card.success(0x35, fields("index", index));
      assertError(transmit(card, 0x40, key(index, "ed25519", BINARY_CONTEXT)), "NOT_FOUND");
      assertError(transmit(card, 0x41, signing(index, BINARY_CONTEXT, MESSAGE)), "NOT_FOUND");
    }
  }

  @Test
  public void rejectsMalformedEd25519DerivationAndSigningRequests() {
    try (Card card = new Card(true)) {
      byte[] index = card.create("seed", null, null, SEED, true);

      for (int instruction : new int[] { 0x40, 0x41 }) {
        for (String invalid : new String[] {
          "curve",
          "path",
          "missing-context",
          "text-context",
          "taproot",
        }) {
          Map<String, Object> derivation = fields(
            "type",
            "monoid-001",
            "curve",
            "ed25519",
            "context",
            BINARY_CONTEXT
          );
          Map<String, Object> request = fields(
            "index",
            index,
            "type",
            "seed",
            "derivation",
            derivation
          );

          if (invalid.equals("curve")) {
            derivation.put("curve", "secp256k1");
          } else if (invalid.equals("path")) {
            derivation.put("path", new byte[0]);
          } else if (invalid.equals("missing-context")) {
            derivation.remove("context");
          } else if (invalid.equals("text-context")) {
            derivation.put("context", "context");
          } else {
            request.put("taproot", false);
          }

          if (instruction == 0x41) {
            request.put("cipher", "ed25519");
            request.put("message", MESSAGE);
          }

          assertError(transmit(card, instruction, request), "INVALID_PARAMETER");
        }
      }

      for (String cipher : new String[] { "ecdsa", "bip340" }) {
        Map<String, Object> request = key(index, "ed25519", BINARY_CONTEXT);
        request.put("cipher", cipher);
        request.put("digest", sequence(32));
        assertError(transmit(card, 0x41, request), "INVALID_PARAMETER");
      }

      Map<String, Object> request = key(index, "ed25519", BINARY_CONTEXT);
      request.put("cipher", "ed25519");
      request.put("digest", sequence(32));
      assertError(transmit(card, 0x41, request), "INVALID_PARAMETER");
    }
  }

  private static void assertVector(
    Card card,
    byte[] index,
    byte[] context,
    byte[] message,
    int vector
  ) {
    Result publicKey = transmit(card, 0x40, key(index, "ed25519", context));
    publicKey.assertSuccess();
    Assertions.assertEquals(1, publicKey.size());
    Assertions.assertArrayEquals(Hex.decode(VECTORS[vector][1]), publicKey.bytes("publicKey"));

    Result signature = transmit(card, 0x41, signing(index, context, message));
    signature.assertSuccess();
    Assertions.assertArrayEquals(Hex.decode(VECTORS[vector][2]), signature.bytes("signature"));
  }

  private static byte[] derive(byte[] seed, byte[] context) throws Exception {
    byte[] label = "Monoid-001".getBytes(StandardCharsets.US_ASCII);
    Mac hmac = Mac.getInstance("HmacSHA512");
    hmac.init(new SecretKeySpec(label, "HmacSHA512"));
    byte[] master = hmac.doFinal(seed);

    hmac.init(new SecretKeySpec(master, "HmacSHA512"));
    hmac.update(label);
    hmac.update((byte) 1);
    hmac.update(context);
    hmac.update((byte) 0);
    return Arrays.copyOf(hmac.doFinal(new byte[] { 1 }), 32);
  }

  private static Map<String, Object> key(byte[] index, String curve, byte[] context) {
    Map<String, Object> derivation = fields("type", "monoid-001");

    if (curve != null) {
      derivation.put("curve", curve);
    }

    derivation.put("context", context);
    return fields("index", index, "type", "seed", "derivation", derivation);
  }

  private static Map<String, Object> signing(byte[] index, byte[] context, byte[] message) {
    Map<String, Object> request = key(index, "ed25519", context);
    request.put("cipher", "ed25519");
    request.put("message", message);
    return request;
  }

  private static Result transmit(Card card, int instruction, Map<String, Object> request) {
    return transmit(card, instruction, request, 255);
  }

  private static Result transmit(
    Card card,
    int instruction,
    Map<String, Object> request,
    int frameLength
  ) {
    CBORBufferWriter writer = new CBORBufferWriter();
    write(writer, request);
    byte[] data = writer.getDataBuffer().clone();
    int frames = 0;

    for (int offset = 0; offset < data.length; offset += frameLength) {
      int end = Math.min(offset + frameLength, data.length);
      boolean last = end == data.length;
      int cla = offset == 0 ? (last ? 0 : 0x90) : (last ? 0xA0 : 0xB0);
      ResponseAPDU response = card.simulator.transmitCommand(
        new CommandAPDU(cla, instruction, 0, 0, Arrays.copyOfRange(data, offset, end))
      );
      frames++;

      if (last) {
        return new Result(response.getData(), response.getSW(), frames, 1);
      }

      Assertions.assertEquals(0x9000, response.getSW());
      Assertions.assertEquals(0, response.getData().length);
    }

    throw new AssertionError("Empty request");
  }

  private static void write(CBORBufferWriter writer, Object value) {
    if (value instanceof Map) {
      Map<?, ?> map = (Map<?, ?>) value;
      writer.map((short) map.size());

      for (Map.Entry<?, ?> entry : map.entrySet()) {
        writer.text(((String) entry.getKey()).getBytes(StandardCharsets.US_ASCII));
        write(writer, entry.getValue());
      }
    } else if (value instanceof byte[]) {
      writer.bytes((byte[]) value);
    } else if (value instanceof String) {
      writer.text(((String) value).getBytes(StandardCharsets.US_ASCII));
    } else {
      writer.bool((Boolean) value);
    }
  }
}
