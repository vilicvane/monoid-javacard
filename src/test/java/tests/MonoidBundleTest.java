package tests;

import static tests.MonoidItemTransferTest.assertCryptoRejected;
import static tests.MonoidItemTransferTest.assertData;
import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.assertMetadata;
import static tests.MonoidItemTransferTest.customIndex;
import static tests.MonoidItemTransferTest.fields;
import static tests.MonoidItemTransferTest.sequence;
import static tests.MonoidItemTransferTest.verifyED25519;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import monoid.MonoidApplet;
import monoid.Safe;
import monoidlib.CBORBufferReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

/** APDU enrollment and item transfer with one active Monoid instance per simulated card. */
public class MonoidBundleTest {

  private static final byte[] ED25519_KEY = Hex.decode(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
  );
  private static final byte[] ED25519_PUBLIC_KEY = Hex.decode(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
  );

  @Test
  public void everyBundleOperationRequiresSecretAuthorization() {
    try (Card peer = new Card(false)) {
      byte[] peerKey = peer.bootstrapPublicKey();

      try (Card card = new Card(true)) {
        byte[] itemIndex = customIndex(200);
        byte[] itemData = sequence(32);
        card.create(itemIndex, null, null, itemData, false);
        List<Map<String, Object>> requests = Arrays.asList(
          fields("publicKeys", new byte[][] { peerKey }),
          fields("publicKey", peerKey, "data", new byte[0])
        );
        int[] instructions = { 0x23, 0x24 };

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

          assertNoBundle(card);
          card.authenticate(false);
          assertData(card, itemIndex, itemData);
        }

        card.authenticate(true);
        Result created = card.success(0x23, requests.get(0));
        byte[] bundle = created.bytes("bundle");
        requirePackets(created, new byte[][] { peerKey });
        assertBundle(card, bundle);
        assertData(card, itemIndex, itemData);
        Assertions.assertEquals(0x6D00, card.transmit(0x29, fields()).status);
      }
    }
  }

  @Test
  public void blockedPINsCanResetAndInitializeAgain() {
    try (Card peer = new Card(false)) {
      byte[] peerKey = peer.bootstrapPublicKey();

      try (Card card = new Card(true)) {
        byte[] publicKey = card.publicKey();
        byte[] identity = card.safeId();
        card.create(customIndex(211), null, "note", sequence(32), false);
        card.create("ed25519", null, "secret key", ED25519_KEY, true);
        Map<String, Object> create = fields("publicKeys", new byte[][] { peerKey });
        card.authenticate(true);
        Result created = card.success(0x23, create);
        byte[] bundle = created.bytes("bundle");
        byte[] data = requirePackets(created, new byte[][] { peerKey }).get(
          Hex.toHexString(peerKey)
        );

        for (boolean safe : new boolean[] { false, true }) {
          for (int remaining = 4; remaining >= 0; remaining--) {
            Result rejected = card.transmit(
              0x21,
              safe ? fields("pin", "000000", "secret", true) : fields("pin", "000000")
            );
            assertError(rejected, "INVALID_PIN");
            CBORBufferReader reader = rejected.reader();
            reader.requireKey("error".getBytes(StandardCharsets.US_ASCII)).map();
            Assertions.assertEquals(
              remaining,
              reader.requireKey("tries".getBytes(StandardCharsets.US_ASCII)).integer()
            );
          }
        }

        List<Map<String, Object>> requests = Arrays.asList(
          create,
          fields("publicKey", publicKey, "data", data)
        );
        int[] instructions = { 0x23, 0x24 };
        for (int index = 0; index < requests.size(); index++) {
          assertError(
            card.transmit(instructions[index], requests.get(index)),
            "SECRET_PIN_BLOCKED"
          );
          assertBundle(card, bundle);
        }

        Assertions.assertEquals(0, card.success(0xFF, fields()).size());
        assertNoBundle(card);
        Assertions.assertFalse(Arrays.equals(identity, card.safeId()));
        Assertions.assertFalse(Arrays.equals(publicKey, card.publicKey()));
        assertPINsUnset(card);
        assertError(card.transmit(0x30, fields()), "UNAUTHORIZED");
        assertError(card.transmit(0x21, fields("pin", "888888", "secret", true)), "PIN_NOT_SET");
        assertError(card.transmit(0x21, fields("pin", "123456")), "PIN_NOT_SET");
        initializePINs(card);
        assertPINTries(card, "secret", 5);
        assertPINTries(card, "access", 5);
        assertEmpty(card);
        card.create(customIndex(211), null, "new note", sequence(32), false);
        assertData(card, customIndex(211), sequence(32));
        card.authenticate(true);
        assertBundle(
          card,
          card.success(0x23, fields("publicKeys", new byte[][] { peerKey })).bytes("bundle")
        );
      }
    }
  }

  @Test
  public void resetDoesNotRequireInitializedPINs() {
    try (Card card = new Card(false)) {
      card.installMonoid(false);
      byte[] identity = card.safeId();
      byte[] publicKey = card.publicKey();

      for (int attempt = 0; attempt < 2; attempt++) {
        Assertions.assertEquals(0, card.success(0xFF, fields()).size());
        byte[] newIdentity = card.safeId();
        byte[] newPublicKey = card.publicKey();
        Assertions.assertFalse(Arrays.equals(identity, newIdentity));
        Assertions.assertFalse(Arrays.equals(publicKey, newPublicKey));
        identity = newIdentity;
        publicKey = newPublicKey;
        assertNoBundle(card);
        assertPINsUnset(card);
        assertError(card.transmit(0x30, fields()), "UNAUTHORIZED");
      }
    }
  }

  @Test
  public void resetRemovesItemsPINsAndBundleAndReplacesIdentity() throws Exception {
    try (Card peer = new Card(false)) {
      byte[] peerKey = peer.bootstrapPublicKey();

      try (Card card = new Card(true)) {
        byte[] identity = card.safeId();
        byte[] publicKey = card.publicKey();
        byte[] plainIndex = customIndex(210);
        for (boolean bundled : new boolean[] { false, true }) {
          card.create(plainIndex, sequence(12), "note", sequence(64), false);
          byte[] secretIndex = card.create("ed25519", null, "secret key", ED25519_KEY, true);
          byte[] seedIndex = card.create("seed", null, "wallet", sequence(64), true);
          card.authenticate(true);
          byte[] bundle = null;
          if (bundled) {
            bundle = card
              .success(0x23, fields("publicKeys", new byte[][] { peerKey }))
              .bytes("bundle");
          }

          Assertions.assertEquals(0x6A80, card.transmit(0x25, fields()).status);

          // A rejected Identity binding must leave both the items and Bundle unchanged.
          Field tokenField = Safe.class.getDeclaredField("identityToken");
          tokenField.setAccessible(true);
          byte[] token = (byte[]) tokenField.get(MonoidApplet.safe);
          token[0] ^= 1;
          try {
            Assertions.assertEquals(0x6982, card.transmit(0xFF, fields()).status);
          } finally {
            token[0] ^= 1;
          }
          assertData(card, plainIndex, sequence(64));
          assertMetadata(card, secretIndex, null, "secret key", true);
          assertMetadata(card, seedIndex, null, "wallet", true);
          if (bundled) {
            assertBundle(card, bundle);
          } else {
            assertNoBundle(card);
          }

          if (bundled) {
            card.reset();
          } else {
            card.authenticate(false);
          }
          Assertions.assertEquals(0, card.success(0xFF, fields()).size());
          assertNoBundle(card);
          assertPINsUnset(card);
          assertError(card.transmit(0x30, fields()), "UNAUTHORIZED");
          assertError(
            card.transmit(0x36, fields("index", plainIndex, "recipientPublicKey", peerKey)),
            "UNAUTHORIZED"
          );
          initializePINs(card);
          card.authenticate(true);
          assertEmpty(card);
          for (byte[] index : new byte[][] { plainIndex, secretIndex, seedIndex }) {
            for (int instruction : new int[] { 0x31, 0x32, 0x36 }) {
              assertError(
                card.transmit(instruction, fields("index", index, "recipientPublicKey", peerKey)),
                "NOT_FOUND"
              );
            }
          }
          assertError(
            card.transmit(0x40, fields("index", secretIndex, "type", "ed25519")),
            "NOT_FOUND"
          );
          assertError(
            card.transmit(
              0x41,
              fields(
                "index",
                secretIndex,
                "type",
                "ed25519",
                "cipher",
                "ed25519",
                "message",
                new byte[] { 0x72 }
              )
            ),
            "NOT_FOUND"
          );
          byte[] newIdentity = card.safeId();
          byte[] newPublicKey = card.publicKey();
          Assertions.assertFalse(Arrays.equals(identity, newIdentity));
          Assertions.assertFalse(Arrays.equals(publicKey, newPublicKey));
          Assertions.assertFalse(Arrays.equals(token, (byte[]) tokenField.get(MonoidApplet.safe)));
          identity = newIdentity;
          publicKey = newPublicKey;
          card.reset();
          Assertions.assertArrayEquals(identity, card.safeId());
          Assertions.assertArrayEquals(publicKey, card.publicKey());
          card.authenticate(false);
          assertEmpty(card);
          card.authenticate(true);
          assertEmpty(card);
        }

        Assertions.assertEquals(0, card.success(0xFF, fields()).size());
        initializePINs(card);
        card.create(plainIndex, null, "new note", sequence(32), false);
        assertData(card, plainIndex, sequence(32));
        byte[] newSecretIndex = card.create("ed25519", null, "new key", ED25519_KEY, true);
        verifyED25519(card, newSecretIndex);
        card.authenticate(true);
        Assertions.assertEquals(1, exportItem(card, plainIndex, peerKey).bytes("data")[0]);
        byte[] bundle = card
          .success(0x23, fields("publicKeys", new byte[][] { peerKey }))
          .bytes("bundle");
        assertBundleEnvelope(exportItem(card, plainIndex, null).bytes("data"), bundle);
      }
    }
  }

  @Test
  public void resetClearsOldAuthorizationBeforeFreshPINSetup() {
    try (Card card = new Card(true)) {
      card.authenticate(true);
      Assertions.assertEquals(0, card.success(0xFF, fields()).size());
      assertPINsUnset(card);
      assertError(card.transmit(0x30, fields()), "UNAUTHORIZED");
      assertError(card.transmit(0x21, fields("pin", "888888", "secret", true)), "PIN_NOT_SET");
      assertError(card.transmit(0x21, fields("pin", "123456")), "PIN_NOT_SET");

      card.success(0x22, fields("pin", "999999", "secret", true));
      assertPINTries(card, "secret", 5);
      assertPINTries(card, "access", 5);
      assertError(card.transmit(0x30, fields()), "UNAUTHORIZED");
      assertError(card.transmit(0x23, fields()), "UNAUTHORIZED");
      assertError(
        card.transmit(0x34, fields("index", customIndex(212), "data", sequence(32))),
        "UNAUTHORIZED"
      );
      assertError(card.transmit(0x21, fields("pin", "888888", "secret", true)), "INVALID_PIN");
      assertError(card.transmit(0x21, fields("pin", "123456")), "INVALID_PIN");
      assertPINTries(card, "secret", 4);
      assertPINTries(card, "access", 4);

      card.success(0x21, fields("pin", "999999", "secret", true));
      card.success(0x22, fields("pin", "654321"));
      card.reset();
      card.success(0x21, fields("pin", "654321"));
      assertEmpty(card);
      card.create(customIndex(212), null, "new note", sequence(32), false);
      assertData(card, customIndex(212), sequence(32));
      card.success(0x21, fields("pin", "999999", "secret", true));
      Assertions.assertEquals(
        1,
        exportItem(card, customIndex(212), card.publicKey()).bytes("data")[0]
      );
    }
  }

  @Test
  public void threeCardsEnrollAndTransferItemsWithoutExposingTheBundleKey() {
    // Each Identity survives while Monoid instances run sequentially: Monoid statics are JVM-wide.
    try (
      Card first = new Card(false);
      Card second = new Card(false);
      Card third = new Card(false);
      Card outsider = new Card(false);
    ) {
      byte[] firstKey = first.bootstrapPublicKey();
      byte[] secondKey = second.bootstrapPublicKey();
      byte[] thirdKey = third.bootstrapPublicKey();
      byte[] outsiderKey = outsider.bootstrapPublicKey();

      byte[][] recipients = { thirdKey, secondKey };
      Arrays.sort(recipients, (left, right) ->
        Hex.toHexString(right).compareTo(Hex.toHexString(left))
      );
      byte[][] members = { firstKey, secondKey, thirdKey };

      byte[] plainIndex = customIndex(201);
      byte[] legacyIndex = customIndex(202);
      byte[] payload = sequence(2048);
      byte[] lookupKey = sequence(12);

      outsider.installMonoid();
      outsider.create(legacyIndex, null, null, sequence(64), false);
      outsider.authenticate(true);
      byte[] legacyData = exportItem(outsider, legacyIndex, firstKey).bytes("data");
      Assertions.assertEquals(1, legacyData[0]);
      outsider.uninstallMonoid();

      first.installMonoid();
      byte[] identity = first.safeId();
      first.create(plainIndex, lookupKey, "large note", payload, false);
      byte[] secretIndex = first.create("ed25519", null, "secret key", ED25519_KEY, true);
      first.authenticate(true);

      Assertions.assertEquals(
        0x6A80,
        first.transmit(0x23, fields("publicKeys", new byte[0][])).status
      );
      assertNoBundle(first);

      assertCryptoRejected(
        first.transmit(0x23, fields("publicKeys", new byte[][] { firstKey, secondKey }))
      );
      assertNoBundle(first);

      assertCryptoRejected(
        first.transmit(0x23, fields("publicKeys", new byte[][] { secondKey, secondKey }))
      );
      assertNoBundle(first);

      byte[] invalidPoint = new byte[65];
      invalidPoint[0] = 4;
      Result invalidPointResult = first.transmit(
        0x23,
        fields("publicKeys", new byte[][] { invalidPoint })
      );
      // jCardSim exposes BouncyCastle's IllegalArgumentException for off-curve points.
      assertError(invalidPointResult, "INTERNAL");
      assertNoBundle(first);

      byte[] asymmetricData = exportItem(first, plainIndex, secondKey).bytes("data");
      Assertions.assertEquals(1, asymmetricData[0]);

      Result created = first.transmit(0x23, fields("publicKeys", recipients), 64);
      created.assertSuccess();

      byte[] bundle = created.bytes("bundle");
      Map<String, byte[]> packets = requirePackets(created, recipients);
      Assertions.assertEquals(32, bundle.length);
      Assertions.assertTrue(created.requestFrames > 1);
      Assertions.assertTrue(created.responseFrames > 1);
      assertBundle(first, bundle);
      Assertions.assertEquals(
        0x6985,
        first.transmit(0x23, fields("publicKeys", recipients)).status
      );
      assertBundle(first, bundle);
      assertData(first, plainIndex, payload);
      assertMetadata(first, secretIndex, null, "secret key", true);

      // The input order is deliberately noncanonical; each returned slot must enroll its recipient.
      byte[] secondEnrollment = packets.get(Hex.toHexString(secondKey));
      byte[] thirdEnrollment = packets.get(Hex.toHexString(thirdKey));
      assertMembers(secondEnrollment, members);
      assertMembers(thirdEnrollment, members);

      first.success(0x37, importItem(legacyIndex, null, null, outsiderKey, legacyData));
      assertData(first, legacyIndex, sequence(64));
      byte[] promotedData = exportItem(first, legacyIndex, null).bytes("data");
      assertBundleEnvelope(promotedData, bundle);

      Result plainExport = exportItem(first, plainIndex, outsiderKey);
      Assertions.assertTrue(plainExport.responseFrames > 1);
      byte[] plainData = plainExport.bytes("data");
      assertBundleEnvelope(plainData, bundle);
      Assertions.assertArrayEquals(firstKey, Arrays.copyOfRange(plainData, 33, 98));
      Assertions.assertEquals(
        0x6985,
        first.transmit(
          0x37,
          importItem(plainIndex, lookupKey, "large note", null, plainData)
        ).status
      );
      byte[] secretData = exportItem(first, secretIndex, null).bytes("data");
      assertBundleEnvelope(secretData, bundle);

      Assertions.assertArrayEquals(identity, first.safeId());
      Assertions.assertArrayEquals(firstKey, first.publicKey());
      first.reset();
      first.authenticate(false);
      assertData(first, plainIndex, payload);
      assertMetadata(first, secretIndex, null, "secret key", true);
      assertBundle(first, bundle);
      first.uninstallMonoid();

      outsider.installMonoid();
      outsider.create(plainIndex, lookupKey, "large note", payload, false);
      outsider.authenticate(true);
      byte[][] otherRecipients = { secondKey };
      Result otherCreated = outsider.success(0x23, fields("publicKeys", otherRecipients));
      byte[] otherBundle = otherCreated.bytes("bundle");
      Assertions.assertFalse(Arrays.equals(bundle, otherBundle));
      byte[] conflictingEnrollment = requirePackets(otherCreated, otherRecipients).get(
        Hex.toHexString(secondKey)
      );
      byte[] foreignData = exportItem(outsider, plainIndex, null).bytes("data");
      outsider.uninstallMonoid();

      second.installMonoid();
      second.authenticate(true);
      byte[] tamperedEnrollment = secondEnrollment.clone();
      tamperedEnrollment[tamperedEnrollment.length - 1] ^= 1;
      assertCryptoRejected(
        second.transmit(0x24, fields("publicKey", firstKey, "data", tamperedEnrollment))
      );
      assertNoBundle(second);
      assertJoined(
        second.success(0x24, fields("publicKey", firstKey, "data", secondEnrollment)),
        bundle
      );
      assertJoined(
        second.success(0x24, fields("publicKey", firstKey, "data", secondEnrollment)),
        bundle
      );
      Assertions.assertEquals(
        0x6985,
        second.transmit(
          0x24,
          fields("publicKey", outsiderKey, "data", conflictingEnrollment)
        ).status
      );
      assertBundle(second, bundle);

      second.authenticate(false);
      assertError(
        second.transmit(0x37, importItem(plainIndex, lookupKey, "large note", null, plainData)),
        "ACCESS_DENIED"
      );
      second.authenticate(true);
      Result plainImport = second.success(
        0x37,
        importItem(plainIndex, lookupKey, "large note", null, plainData)
      );
      Assertions.assertTrue(plainImport.requestFrames > 1);
      assertData(second, plainIndex, payload);
      second.success(0x37, importItem(secretIndex, null, "secret key", null, secretData));
      assertMetadata(second, secretIndex, null, "secret key", true);
      assertError(second.transmit(0x32, fields("index", secretIndex)), "ACCESS_DENIED");
      Assertions.assertArrayEquals(
        ED25519_PUBLIC_KEY,
        second.success(0x40, fields("index", secretIndex, "type", "ed25519")).bytes("publicKey")
      );
      second.success(0x37, importItem(legacyIndex, null, null, null, promotedData));
      assertData(second, legacyIndex, sequence(64));
      second.success(
        0x37,
        importItem(plainIndex, lookupKey, "large note", firstKey, asymmetricData)
      );

      byte[] tamperedData = plainData.clone();
      tamperedData[tamperedData.length - 1] ^= 1;
      assertCryptoRejected(
        second.transmit(0x37, importItem(plainIndex, lookupKey, "large note", null, tamperedData))
      );
      assertCryptoRejected(
        second.transmit(0x37, importItem(plainIndex, lookupKey, "changed", null, plainData))
      );
      Assertions.assertEquals(
        0x6985,
        second.transmit(
          0x37,
          importItem(plainIndex, lookupKey, "large note", null, foreignData)
        ).status
      );
      assertData(second, plainIndex, payload);
      assertMetadata(second, plainIndex, lookupKey, "large note", false);
      second.authenticate(true);
      byte[] relayedData = exportItem(second, plainIndex, null).bytes("data");
      second.uninstallMonoid();

      third.installMonoid();
      third.authenticate(true);
      assertJoined(
        third.success(0x24, fields("publicKey", firstKey, "data", thirdEnrollment)),
        bundle
      );
      third.success(0x37, importItem(plainIndex, lookupKey, "large note", null, relayedData));
      assertData(third, plainIndex, payload);
      third.uninstallMonoid();

      // Replacing Monoid keeps the member identity and its original Secret PIN.
      first.installMonoid(false);
      assertError(
        first.transmit(0x37, importItem(plainIndex, lookupKey, "large note", null, relayedData)),
        "UNAUTHORIZED"
      );
      assertError(first.transmit(0x22, fields("pin", "111111", "secret", true)), "UNAUTHORIZED");
      first.authenticate(true);
      first.success(0x37, importItem(plainIndex, lookupKey, "large note", null, relayedData));
      assertData(first, plainIndex, payload);
      Assertions.assertEquals(
        0x6985,
        first.transmit(
          0x37,
          importItem(plainIndex, lookupKey, "large note", null, plainData)
        ).status
      );
      first.uninstallMonoid();

      outsider.installMonoid();
      outsider.authenticate(true);
      Assertions.assertEquals(
        0x6985,
        outsider.transmit(0x24, fields("publicKey", firstKey, "data", secondEnrollment)).status
      );
      assertBundle(outsider, otherBundle);
      Assertions.assertEquals(
        0x6985,
        outsider.transmit(
          0x37,
          importItem(plainIndex, lookupKey, "large note", null, plainData)
        ).status
      );
      assertError(outsider.transmit(0x31, fields("index", plainIndex)), "NOT_FOUND");
    }
  }

  private static Result exportItem(Card card, byte[] index, byte[] recipient) {
    Map<String, Object> request = fields("index", index);
    if (recipient != null) {
      request.put("recipientPublicKey", recipient);
    }
    return card.success(0x36, request);
  }

  private static Map<String, Object> importItem(
    byte[] index,
    byte[] key,
    String alias,
    byte[] sender,
    byte[] data
  ) {
    Map<String, Object> request = fields("index", index);
    if (sender != null) {
      request.put("senderPublicKey", sender);
    }
    if (key != null) {
      request.put("key", key);
    }
    if (alias != null) {
      request.put("alias", alias);
    }
    request.put("data", data);
    return request;
  }

  private static void assertNoBundle(Card card) {
    CBORBufferReader reader = card.success(0x20, fields()).reader();
    Assertions.assertFalse(reader.requireKey("bundle".getBytes(StandardCharsets.US_ASCII)).bool());
  }

  private static void assertEmpty(Card card) {
    CBORBufferReader reader = card.success(0x30, fields()).reader();
    Assertions.assertEquals(
      0,
      reader.requireKey("items".getBytes(StandardCharsets.US_ASCII)).array()
    );
  }

  private static void assertPINTries(Card card, String pin, int tries) {
    CBORBufferReader reader = card.success(0x20, fields()).reader();
    reader.requireKey("pins".getBytes(StandardCharsets.US_ASCII)).map();
    Assertions.assertEquals(
      tries,
      reader.requireKey(pin.getBytes(StandardCharsets.US_ASCII)).integer()
    );
  }

  private static void assertPINsUnset(Card card) {
    CBORBufferReader reader = card.success(0x20, fields()).reader();
    reader.requireKey("pins".getBytes(StandardCharsets.US_ASCII)).map();
    Assertions.assertFalse(reader.requireKey("access".getBytes(StandardCharsets.US_ASCII)).bool());
    Assertions.assertFalse(reader.requireKey("secret".getBytes(StandardCharsets.US_ASCII)).bool());
  }

  private static void initializePINs(Card card) {
    card.success(0x22, fields("pin", "888888", "secret", true));
    assertError(card.transmit(0x30, fields()), "UNAUTHORIZED");
    card.authenticate(true);
    card.success(0x22, fields("pin", "123456"));
    card.authenticate(false);
  }

  private static void assertJoined(Result result, byte[] bundle) {
    Assertions.assertEquals(1, result.size());
    Assertions.assertArrayEquals(bundle, result.bytes("bundle"));
  }

  private static Map<String, byte[]> requirePackets(Result result, byte[][] recipients) {
    Assertions.assertEquals(2, result.size());
    Map<String, byte[]> packets = new LinkedHashMap<>();
    CBORBufferReader reader = result.reader();
    Assertions.assertEquals(
      recipients.length,
      reader.requireKey("data".getBytes(StandardCharsets.US_ASCII)).array()
    );

    for (short index = 0; index < recipients.length; index++) {
      Assertions.assertTrue(reader.index(index));
      packets.put(Hex.toHexString(recipients[index]), reader.bytes().clone());
    }

    return packets;
  }

  private static void assertBundle(Card card, byte[] bundle) {
    Assertions.assertArrayEquals(bundle, card.success(0x20, fields()).bytes("bundle"));
  }

  private static void assertBundleEnvelope(byte[] data, byte[] bundle) {
    Assertions.assertEquals(2, data[0]);
    Assertions.assertArrayEquals(bundle, Arrays.copyOfRange(data, 1, 33));
  }

  private static void assertMembers(byte[] data, byte[][] members) {
    byte[][] sorted = members.clone();
    Arrays.sort(sorted, (left, right) -> Hex.toHexString(left).compareTo(Hex.toHexString(right)));
    Assertions.assertEquals(1, data[0]);
    Assertions.assertEquals(members.length, ((data[1] & 0xFF) << 8) | (data[2] & 0xFF));
    for (int index = 0; index < sorted.length; index++) {
      Assertions.assertArrayEquals(
        sorted[index],
        Arrays.copyOfRange(data, 3 + index * 65, 3 + (index + 1) * 65)
      );
    }
  }
}
