package tests;

import static tests.MonoidItemTransferTest.assertData;
import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.customIndex;
import static tests.MonoidItemTransferTest.fields;
import static tests.MonoidItemTransferTest.sequence;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import monoidlib.CBORBufferReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

public class MonoidBundleExtensionTest {

  @Test
  public void bothCommandsRequireSecretAuthorizationAndAnExistingBundle() {
    try (Card card = new Card(true)) {
      List<Map<String, Object>> requests = Arrays.asList(
        fields("publicKey", card.publicKey()),
        fields("data", new byte[0])
      );
      int[] instructions = { 0x25, 0x26 };

      for (boolean access : new boolean[] { false, true }) {
        card.reset();
        if (access) {
          card.authenticate(false);
        }

        for (int index = 0; index < requests.size(); index++) {
          assertError(
            card.transmit(instructions[index], requests.get(index)),
            access ? "ACCESS_DENIED" : "UNAUTHORIZED"
          );
        }
      }

      card.authenticate(true);

      for (int index = 0; index < requests.size(); index++) {
        Assertions.assertEquals(
          0x6985,
          card.transmit(instructions[index], requests.get(index)).status
        );
      }

      CBORBufferReader hello = card.success(0x20, fields()).reader();
      Assertions.assertFalse(hello.requireKey(bytes("bundle")).bool());
    }
  }

  @Test
  public void requiredFieldsAreValidatedBeforeBundleAccess() {
    try (Card card = new Card(true)) {
      card.authenticate(true);

      List<Map<String, Object>> requests = Arrays.asList(
        fields(),
        fields("publicKey", new byte[64]),
        fields("publicKey", "not bytes")
      );

      for (Map<String, Object> request : requests) {
        Assertions.assertEquals(0x6A80, card.transmit(0x25, request).status);
      }

      for (Map<String, Object> request : Arrays.asList(fields(), fields("data", "not bytes"))) {
        Assertions.assertEquals(0x6A80, card.transmit(0x26, request).status);
      }
    }
  }

  @Test
  public void threeStepsAdmitANewCardWithoutSynchronizingExistingCards() {
    // Keep Identity instances while selecting one Monoid at a time: its statics are JVM-wide.
    try (
      Card first = new Card(false);
      Card second = new Card(false);
      Card third = new Card(false);
      Card fourth = new Card(false);
    ) {
      byte[] firstKey = first.bootstrapPublicKey();
      byte[] secondKey = second.bootstrapPublicKey();
      byte[] thirdKey = third.bootstrapPublicKey();
      byte[] fourthKey = fourth.bootstrapPublicKey();
      byte[] originalIndex = customIndex(220);
      byte[] replyIndex = customIndex(221);
      byte[] original = sequence(384);
      byte[] reply = sequence(64);

      first.installMonoid();
      first.create(originalIndex, null, null, original, false);
      first.authenticate(true);
      Result created = first.success(0x23, fields("publicKeys", new byte[][] { secondKey }));
      byte[] bundle = created.bytes("bundle");
      byte[] secondEnrollment = enrollment(created);
      byte[] originalEnvelope = first.success(0x36, fields("index", originalIndex)).bytes("data");

      Result extended = first.success(0x25, fields("publicKey", thirdKey));
      Assertions.assertEquals(1, extended.size());
      Assertions.assertTrue(extended.responseFrames > 1);
      Map<String, Object> request = responseFields(extended);

      Assertions.assertEquals(0x6985, first.transmit(0x26, request).status);
      assertBundle(first, bundle);
      first.uninstallMonoid();

      second.installMonoid();
      second.authenticate(true);

      assertBundleResult(
        second.success(0x24, fields("publicKey", firstKey, "data", secondEnrollment)),
        bundle
      );

      Result approved = second.success(0x26, request);
      Assertions.assertEquals(2, approved.size());
      Assertions.assertTrue(approved.requestFrames > 1);
      Assertions.assertTrue(approved.responseFrames > 1);
      Assertions.assertArrayEquals(secondKey, approved.bytes("publicKey"));
      Map<String, Object> thirdEnrollment = responseFields(approved);

      Result approvedAgain = second.success(0x26, request);
      Assertions.assertEquals(2, approvedAgain.size());
      Assertions.assertArrayEquals(secondKey, approvedAgain.bytes("publicKey"));
      Map<String, Object> repeatedEnrollment = responseFields(approvedAgain);
      assertBundle(second, bundle);
      second.uninstallMonoid();

      third.installMonoid();
      third.authenticate(true);

      // Forward B's response fields without renaming them or supplying its public key externally.
      for (Map<String, Object> data : Arrays.asList(thirdEnrollment, repeatedEnrollment)) {
        assertBundleResult(third.success(0x24, data), bundle);
      }

      // A has not been visited since requesting extension; its previous ciphertext already works.
      third.success(0x37, fields("index", originalIndex, "data", originalEnvelope));
      assertData(third, originalIndex, original);
      third.create(replyIndex, null, null, reply, false);
      byte[] replyEnvelope = third.success(0x36, fields("index", replyIndex)).bytes("data");

      Map<String, Object> fourthRequest = responseFields(
        third.success(0x25, fields("publicKey", fourthKey))
      );
      third.uninstallMonoid();

      // This visit performs actual use, with no member-list synchronization beforehand.
      first.installMonoid();
      first.authenticate(true);
      first.success(0x37, fields("index", replyIndex, "data", replyEnvelope));
      assertData(first, replyIndex, reply);

      Result fourthApproved = first.success(0x26, fourthRequest);
      Assertions.assertEquals(2, fourthApproved.size());
      Assertions.assertArrayEquals(firstKey, fourthApproved.bytes("publicKey"));
      Map<String, Object> fourthEnrollment = responseFields(fourthApproved);
      assertBundle(first, bundle);
      first.uninstallMonoid();

      fourth.installMonoid();
      fourth.authenticate(true);
      assertBundleResult(fourth.success(0x24, fourthEnrollment), bundle);
      fourth.success(0x37, fields("index", originalIndex, "data", originalEnvelope));
      assertData(fourth, originalIndex, original);
      fourth.success(0x37, fields("index", replyIndex, "data", replyEnvelope));
      assertData(fourth, replyIndex, reply);
    }
  }

  private static byte[] enrollment(Result created) {
    Assertions.assertEquals(2, created.size());

    CBORBufferReader reader = created.reader();
    Assertions.assertEquals(1, reader.requireKey(bytes("data")).array());
    Assertions.assertTrue(reader.index((short) 0));

    return reader.bytes().clone();
  }

  private static Map<String, Object> responseFields(Result response) {
    Map<String, Object> request = fields();
    CBORBufferReader reader = response.reader();
    int count = response.size();

    for (int index = 0; index < count; index++) {
      String field = new String(reader.text(), StandardCharsets.US_ASCII);
      request.put(field, reader.bytes().clone());
    }

    return request;
  }

  private static void assertBundleResult(Result result, byte[] bundle) {
    Assertions.assertEquals(1, result.size());
    Assertions.assertArrayEquals(bundle, result.bytes("bundle"));
  }

  private static void assertBundle(Card card, byte[] bundle) {
    Assertions.assertArrayEquals(bundle, card.success(0x20, fields()).bytes("bundle"));
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }
}
