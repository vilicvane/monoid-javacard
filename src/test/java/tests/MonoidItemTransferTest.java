package tests;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javacard.framework.AID;
import javacard.security.CryptoException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoid.CBORBufferReader;
import monoid.CBORBufferWriter;
import monoid.MonoidApplet;
import monoid.Safe;
import monoididentity.MonoidIdentityApplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** Complete APDU flows; the simulator models SIO callers, not the card firewall. */
public class MonoidItemTransferTest {

  private static final AID IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_IDENTITY_AID}}"
    "f06d6f6e6f69640001"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );
  private static final AID IDENTITY_CALLER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_NAMESPACE}}7f11"
    "f06d6f6e6f69647f11"
  );

  private static final String SAFE_PIN = "888888";
  private static final String ACCESS_PIN = "123456";

  private static final byte[] SEED = Hex.decode(
    "3100314ef25741e991c7bea11a7542b31d873d45a4b6c3da120d8a60553095ddc9a72a1a46e397495402ab9a2fa1190d62d07480275dc91faf12187d46aa0b63"
  );
  private static final byte[] SECP256K1_KEY = Hex.decode(
    "eff3af6963c58a7a8ad2462bd41486d0a146d8850bd497234da6d419041f4c58"
  );
  private static final byte[] ED25519_KEY = Hex.decode(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
  );
  private static final byte[] DIGEST = Hex.decode(
    "43ddcab065bcc7bd8d80c479ed29d3658ccf3ac3343b7044013008bde5ca19cf"
  );

  @Test
  public void getAndSecretUpdatesUseOrdinaryAuthentication() {
    try (Card card = new Card(true)) {
      byte[] publicKey = card.publicKey();
      Assertions.assertEquals(65, publicKey.length);
      Assertions.assertEquals(4, publicKey[0]);

      byte[] index = customIndex(1);
      byte[] data = { 1, 2, 3 };
      byte[] key = { 4, 5 };
      card.create(index, key, "plain", data, null);
      assertMetadata(card, index, key, "plain", false);
      assertData(card, index, data);
      assertListedSecret(card, index, false);

      byte[] secretIndex = customIndex(2);
      card.create(secretIndex, null, null, new byte[] { 6 }, true);
      assertMetadata(card, secretIndex, null, null, true);
      assertListedSecret(card, secretIndex, true);
      assertError(card.transmit(0x32, fields("index", secretIndex)), "ACCESS_DENIED");

      // A data-only update preserves the flag; tightening does not require replacement data.
      card.success(0x33, fields("index", secretIndex, "data", new byte[] { 7 }));
      assertMetadata(card, secretIndex, null, null, true);
      card.success(0x33, fields("index", index, "secret", true));
      assertError(card.transmit(0x32, fields("index", index)), "ACCESS_DENIED");

      Result denied = card.transmit(
        0x33,
        fields("index", index, "alias", "changed", "secret", false)
      );
      Assertions.assertEquals(0x6985, denied.status);
      assertMetadata(card, index, key, "plain", true);

      byte[] replacement = { 8, 9 };
      card.success(0x33, fields("index", index, "secret", false, "data", replacement));
      assertMetadata(card, index, key, "plain", false);
      assertData(card, index, replacement);

      card.success(0x33, fields("index", index, "secret", true, "data", new byte[] { 10 }));
      assertMetadata(card, index, key, "plain", true);
      assertError(card.transmit(0x32, fields("index", index)), "ACCESS_DENIED");
      card.success(0x33, fields("index", index, "secret", false, "data", new byte[0]));
      assertData(card, index, new byte[0]);

      assertError(card.transmit(0x33, fields("index", customIndex(3), "data", data)), "NOT_FOUND");
      assertAbsent(card, customIndex(3));

      card.authenticate(true);
      assertError(card.transmit(0x32, fields("index", secretIndex)), "ACCESS_DENIED");
      card.reset();
      assertError(card.transmit(0x32, fields("index", index)), "UNAUTHORIZED");
      card.authenticate(false);
      assertData(card, index, new byte[0]);
    }
  }

  @Test
  public void randomItemsAreSecretForEverySupportedKeyType() {
    try (Card card = new Card(true)) {
      String[] types = { "entropy", "seed", "secp256k1", "secp256r1", "ed25519" };

      for (String type : types) {
        Map<String, Object> request = fields("type", type);
        if (type.equals("entropy") || type.equals("seed")) {
          request.put("length", type.equals("seed") ? 64 : 32);
        }

        byte[] index = card.success(0x38, request).bytes("index");
        assertMetadata(card, index, null, null, true);
        assertListedSecret(card, index, true);
        assertError(card.transmit(0x32, fields("index", index)), "ACCESS_DENIED");
      }

      Assertions.assertEquals(types.length, itemCount(card));
    }
  }

  @Test
  public void removedMasterTypeIsRejectedByPublicCommands() {
    try (Card card = new Card(true)) {
      assertError(card.transmit(0x30, fields("type", "master")), "INVALID_PARAMETER");
      assertError(card.transmit(0x34, fields("type", "master", "data", SEED)), "INVALID_PARAMETER");
      assertError(card.transmit(0x38, fields("type", "master", "length", 32)), "INVALID_PARAMETER");

      // A former 32B-key/32B-chain-code item is no longer a recognized item type.
      assertError(card.transmit(0x34, fields("type", 0x0320, "data", SEED)), "INVALID_PARAMETER");
      byte[] oldIndex = new byte[Safe.INDEX_LENGTH];
      oldIndex[0] = 3;
      oldIndex[1] = 32;
      assertError(
        card.transmit(0x34, fields("index", oldIndex, "data", SEED)),
        "INVALID_PARAMETER"
      );
      Assertions.assertEquals(0, itemCount(card));

      byte[] index = card.create("seed", null, null, SEED, false);

      for (int instruction : new int[] { 0x40, 0x41 }) {
        Map<String, Object> request = fields("index", index, "type", "master");

        if (instruction == 0x41) {
          request.put("cipher", "ecdsa");
          request.put("digest", DIGEST);
        }

        assertError(card.transmit(instruction, request), "INVALID_PARAMETER");
      }

      assertData(card, index, SEED);
    }
  }

  @Test
  public void curveItemTypesUseTheRenumberedCategories() {
    try (Card card = new Card(true)) {
      String[] names = { "secp256k1", "secp256r1", "ed25519" };
      short[] types = { 0x0301, 0x0302, 0x0401 };
      byte[] scalar = new byte[32];
      scalar[31] = 1;

      for (int position = 0; position < types.length; position++) {
        byte[] index = card.create(names[position], null, null, scalar, false);
        Assertions.assertEquals(types[position] >> 8, index[0] & 0xFF);
        Assertions.assertEquals(types[position] & 0xFF, index[1] & 0xFF);
        card.success(0x35, fields("index", index));
        Assertions.assertArrayEquals(
          index,
          card.success(0x34, fields("type", types[position], "data", scalar)).bytes("index")
        );

        CBORBufferReader reader = card.success(0x30, fields("type", types[position])).reader();
        Assertions.assertEquals(1, reader.requireKey(bytes("items")).array());
        Assertions.assertTrue(reader.index((short) 0));
        reader.map();
        Assertions.assertArrayEquals(
          bytes(names[position]),
          reader.requireKey(bytes("type")).text()
        );
      }

      for (int category : new int[] { 0x0300, 0x0400 }) {
        CBORBufferReader reader = card.success(0x30, fields("type", category)).reader();
        short count = reader.requireKey(bytes("items")).array();
        Assertions.assertEquals(category == 0x0300 ? 2 : 1, count);

        for (short position = 0; position < count; position++) {
          Assertions.assertTrue(reader.index(position));
          reader.map();
          Assertions.assertEquals(category >> 8, reader.requireKey(bytes("index")).bytes()[0]);
        }
      }
    }
  }

  @Test
  public void selectedItemsTransferBetweenCardsAndSecretKeysStillSign() throws Exception {
    // Only one Monoid instance is active at a time: its static fields are JVM-wide.
    // The target Identity is prepared first; source operations finish before target Monoid installs.
    try (Card target = new Card(false)) {
      byte[] recipient = target.bootstrapPublicKey();
      byte[] sender;
      List<Transfer> transfers = new ArrayList<>();
      byte[] plainIndex = customIndex(10);
      byte[] seedIndex;
      byte[] ecdsaIndex;
      byte[] ed25519Index;

      try (Card source = new Card(true)) {
        sender = source.publicKey();
        Assertions.assertFalse(Arrays.equals(sender, recipient));
        source.create(plainIndex, new byte[] { 1, 2 }, "note", sequence(64), null);
        seedIndex = source.create("seed", sequence(16), "wallet", SEED, true);
        ecdsaIndex = source.create("secp256k1", null, "bitcoin", SECP256K1_KEY, true);
        ed25519Index = source.create("ed25519", null, "solana", ED25519_KEY, true);
        source.create(customIndex(11), null, "not selected", new byte[] { 42 }, false);
        assertECDSAKeyAndSimulatorLimitation(source, ecdsaIndex);

        assertError(
          source.transmit(0x36, fields("index", plainIndex, "recipientPublicKey", recipient)),
          "ACCESS_DENIED"
        );
        source.authenticate(true);
        for (byte[] index : new byte[][] { plainIndex, seedIndex, ecdsaIndex, ed25519Index }) {
          transfers.add(source.export(index, recipient));
        }
      }

      target.installMonoid();
      Assertions.assertArrayEquals(recipient, target.publicKey());

      for (Transfer transfer : transfers) {
        Assertions.assertEquals(0, target.success(0x37, transfer.request(sender)).size());
      }

      Assertions.assertEquals(4, itemCount(target));
      assertAbsent(target, customIndex(11));
      assertData(target, plainIndex, sequence(64));
      assertMetadata(target, seedIndex, sequence(16), "wallet", true);
      assertError(target.transmit(0x32, fields("index", seedIndex)), "ACCESS_DENIED");
      assertECDSAKeyAndSimulatorLimitation(target, ecdsaIndex);
      verifyED25519(target, ed25519Index);

      // No sender-registration step exists; the caller supplies the expected full public key.
      for (Transfer transfer : transfers) {
        Assertions.assertEquals(0, target.success(0x37, transfer.request(sender)).size());
      }
      Assertions.assertEquals(4, itemCount(target));
    }
  }

  @Test
  public void conflictingImportsDoNotOverwriteExistingItems() {
    try (Card card = new Card(true)) {
      byte[] index = customIndex(20);
      byte[] key = { 1, 2 };
      byte[] data = { 3, 4 };
      card.create(index, key, "original", data, false);
      byte[] sender = card.publicKey();
      card.authenticate(true);
      Transfer transfer = card.export(index, sender);
      card.success(0x35, fields("index", index));
      card.authenticate(false);

      for (int difference = 0; difference < 4; difference++) {
        byte[] existingKey = difference == 0 ? new byte[] { 5 } : key;
        String existingAlias = difference == 1 ? "other" : "original";
        byte[] existingData = difference == 2 ? new byte[] { 6 } : data;
        boolean existingSecret = difference == 3;
        card.create(index, existingKey, existingAlias, existingData, existingSecret);

        Assertions.assertEquals(0x6985, card.transmit(0x37, transfer.request(sender)).status);
        Assertions.assertEquals(1, itemCount(card));
        assertMetadata(card, index, existingKey, existingAlias, existingSecret);
        if (existingSecret) {
          assertError(card.transmit(0x32, fields("index", index)), "ACCESS_DENIED");
        } else {
          assertData(card, index, existingData);
        }
        card.success(0x35, fields("index", index));
      }

      card.success(0x37, transfer.request(sender));
      card.success(0x37, transfer.request(sender));
      Assertions.assertEquals(1, itemCount(card));
      assertData(card, index, data);
    }
  }

  @Test
  public void tamperedItemsNeverPublishAndDoNotPreventTheNextImport() {
    try (Card card = new Card(true)) {
      byte[] index = customIndex(30);
      byte[] sender = card.publicKey();
      byte[] data = sequence(64);
      card.create(index, new byte[] { 1, 2, 3 }, "record", data, false);
      card.authenticate(true);
      Transfer transfer = card.export(index, sender);
      byte[] otherPublicKey = SECNamedCurves.getByName("secp256r1").getG().getEncoded(false);
      Transfer otherRecipient = card.export(index, otherPublicKey);
      card.success(0x35, fields("index", index));
      card.authenticate(false);

      List<Map<String, Object>> invalidRequests = new ArrayList<>();
      for (int offset : new int[] { 0, Safe.INDEX_LENGTH - 1 }) {
        byte[] changed = index.clone();
        changed[offset] ^= 1;
        Map<String, Object> request = transfer.request(sender);
        request.put("index", changed);
        invalidRequests.add(request);
      }
      Map<String, Object> changedKey = transfer.request(sender);
      changedKey.put("key", new byte[] { 1, 2, 4 });
      invalidRequests.add(changedKey);
      Map<String, Object> changedAlias = transfer.request(sender);
      changedAlias.put("alias", "Record");
      invalidRequests.add(changedAlias);
      invalidRequests.add(transfer.request(otherPublicKey));
      invalidRequests.add(otherRecipient.request(sender));

      // Version, encapsulation, nonce, payload and tag are independently authenticated.
      for (int offset : new int[] {
        0,
        70,
        114,
        transfer.data.length - 20,
        transfer.data.length - 1,
      }) {
        byte[] changed = transfer.data.clone();
        changed[offset] ^= 1;
        Map<String, Object> request = transfer.request(sender);
        request.put("data", changed);
        invalidRequests.add(request);
      }
      Map<String, Object> truncated = transfer.request(sender);
      truncated.put("data", Arrays.copyOf(transfer.data, transfer.data.length - 1));
      invalidRequests.add(truncated);

      for (Map<String, Object> request : invalidRequests) {
        assertCryptoRejected(card.transmit(0x37, request));
        assertAbsent(card, (byte[]) request.get("index"));
        Assertions.assertEquals(0, itemCount(card));
        card.success(0x37, transfer.request(sender));
        assertData(card, index, data);
        card.success(0x35, fields("index", index));
      }

      card.reset();
      assertError(card.transmit(0x37, transfer.request(sender)), "UNAUTHORIZED");
      card.authenticate(false);
      card.success(0x37, transfer.request(sender));
      assertData(card, index, data);
    }
  }

  @Test
  public void missingAndEmptyMetadataRemainDistinct() {
    try (Card card = new Card(true)) {
      byte[] sender = card.publicKey();

      for (boolean present : new boolean[] { false, true }) {
        byte[] index = customIndex(present ? 41 : 40);
        byte[] key = present ? new byte[0] : null;
        String alias = present ? "" : null;
        card.create(index, key, alias, new byte[] { 1 }, false);
        card.authenticate(true);
        Transfer transfer = card.export(index, sender);
        Assertions.assertEquals(present, transfer.key != null);
        Assertions.assertEquals(present, transfer.alias != null);
        card.success(0x35, fields("index", index));
        card.authenticate(false);

        for (String field : new String[] { "key", "alias" }) {
          Map<String, Object> altered = transfer.request(sender);
          if (present) {
            altered.remove(field);
          } else {
            altered.put(field, field.equals("key") ? new byte[0] : "");
          }
          assertCryptoRejected(card.transmit(0x37, altered));
          assertAbsent(card, index);
        }

        card.success(0x37, transfer.request(sender));
        assertMetadata(card, index, key, alias, false);
        card.success(0x37, transfer.request(sender));
      }

      Assertions.assertEquals(2, itemCount(card));
    }
  }

  @Test
  public void fragmentedPayloadsSurviveResetAndAbandonedRequests() {
    try (Card card = new Card(true)) {
      byte[] sender = card.publicKey();

      for (int length : new int[] { 256, 512 }) {
        byte[] index = customIndex(length);
        byte[] data = sequence(length);
        byte[] key = sequence(16);
        Result created = card.transmit(
          0x34,
          fields("index", index, "key", key, "alias", "chunked", "data", data)
        );
        created.assertSuccess();
        Assertions.assertTrue(created.requestFrames > 1);
        card.authenticate(true);
        Transfer transfer = card.export(index, sender);
        Assertions.assertTrue(transfer.responseFrames > 1);
        card.success(0x35, fields("index", index));

        card.reset();
        card.authenticate(false);
        byte[] request = encode(transfer.request(sender));
        ResponseAPDU first = card.simulator.transmitCommand(
          new CommandAPDU(0x90, 0x37, 0, 0, Arrays.copyOf(request, 128))
        );
        Assertions.assertEquals(0x9000, first.getSW());
        Assertions.assertEquals(0, first.getData().length);
        card.success(0x20, fields());
        assertAbsent(card, index);

        Result imported = card.transmit(0x37, transfer.request(sender), 128);
        imported.assertSuccess();
        Assertions.assertEquals(0, imported.size());
        Assertions.assertTrue(imported.requestFrames > 1);
        Result fetched = card.success(0x32, fields("index", index));
        Assertions.assertEquals(1, fetched.size());
        Assertions.assertTrue(fetched.responseFrames > 1);
        Assertions.assertArrayEquals(data, fetched.bytes("data"));
        assertMetadata(card, index, key, "chunked", false);
      }

      Assertions.assertEquals(2, itemCount(card));
    }
  }

  @Test
  public void largeItemsUseFragmentedRequestsAndResponses() {
    try (Card card = new Card(true)) {
      byte[] index = customIndex(60);
      byte[] key = sequence(16);
      byte[] data = sequence(4097);
      data[2048] = 42;
      Result created = card.transmit(
        0x34,
        fields("data", data, "alias", "large", "index", index, "key", key),
        127
      );
      created.assertSuccess();
      Assertions.assertTrue(created.requestFrames > 1);
      Assertions.assertArrayEquals(index, created.bytes("index"));
      Result fetched = card.success(0x32, fields("index", index));
      Assertions.assertTrue(fetched.responseFrames > 1);
      Assertions.assertArrayEquals(data, fetched.bytes("data"));

      byte[] replacement = sequence(6145);
      replacement[4096] = 99;
      Result updated = card.transmit(
        0x33,
        fields("index", index, "data", replacement, "secret", false),
        193
      );
      updated.assertSuccess();
      Assertions.assertTrue(updated.requestFrames > 1);
      assertData(card, index, replacement);
      assertMetadata(card, index, key, "large", false);

      for (boolean reset : new boolean[] { false, true }) {
        byte[] request = encode(fields("index", index, "data", data, "secret", true));

        for (int offset = 0; offset < 510; offset += 255) {
          ResponseAPDU response = card.simulator.transmitCommand(
            new CommandAPDU(
              offset == 0 ? 0x90 : 0xB0,
              0x33,
              0,
              0,
              Arrays.copyOfRange(request, offset, offset + 255)
            )
          );
          Assertions.assertEquals(0x9000, response.getSW());
          Assertions.assertEquals(0, response.getData().length);
        }

        if (reset) {
          card.reset();
          card.authenticate(false);
        } else {
          card.success(0x20, fields());
        }

        assertData(card, index, replacement);
        assertMetadata(card, index, key, "large", false);

        ResponseAPDU first = card.simulator.transmitCommand(
          new CommandAPDU(0, 0x32, 0, 0, encode(fields("index", index)))
        );
        Assertions.assertEquals(0x6100, first.getSW());

        if (reset) {
          card.reset();
          card.authenticate(false);
        } else {
          card.success(0x20, fields());
        }

        Assertions.assertEquals(
          0x6985,
          card.simulator.transmitCommand(new CommandAPDU(0, 0xC0, 0, 0, 256)).getSW()
        );
        assertData(card, index, replacement);
      }

      card.success(0x33, fields("index", index, "data", data, "secret", true));
      assertMetadata(card, index, key, "large", true);
      assertError(card.transmit(0x32, fields("index", index)), "ACCESS_DENIED");
    }
  }

  @Test
  public void largeImportsVerifyEveryChunkBeforePublishingOrMatchingExistingData() {
    try (Card card = new Card(true)) {
      byte[] index = customIndex(61);
      byte[] key = sequence(16);
      byte[] data = sequence(4097);
      data[2048] = 42;
      card.create(index, key, "large transfer", data, false);
      byte[] sender = card.publicKey();
      card.authenticate(true);
      Transfer transfer = card.export(index, sender);
      Assertions.assertTrue(transfer.responseFrames > 1);
      card.success(0x35, fields("index", index));
      card.authenticate(false);

      byte[] changed = transfer.data.clone();
      changed[2048] ^= 1;
      Map<String, Object> tampered = transfer.request(sender);
      tampered.put("data", changed);
      assertCryptoRejected(card.transmit(0x37, tampered));
      assertAbsent(card, index);

      Result imported = card.transmit(0x37, transfer.request(sender), 193);
      imported.assertSuccess();
      Assertions.assertTrue(imported.requestFrames > 1);
      assertData(card, index, data);
      assertMetadata(card, index, key, "large transfer", false);
      card.success(0x37, transfer.request(sender));
      Assertions.assertEquals(1, itemCount(card));

      byte[] replacement = data.clone();
      replacement[replacement.length - 1] ^= 1;
      card.success(0x33, fields("index", index, "data", replacement));
      Assertions.assertEquals(0x6985, card.transmit(0x37, transfer.request(sender)).status);
      assertData(card, index, replacement);
      assertMetadata(card, index, key, "large transfer", false);
    }
  }

  @Test
  public void digestIndexedItemsHashTheEntireDataSource() throws Exception {
    try (Card card = new Card(true)) {
      for (int length : new int[] { 255, 32, 64, 252 }) {
        byte[] data = sequence(length);
        byte[] expectedIndex = new byte[Safe.INDEX_LENGTH];
        expectedIndex[0] = 2;
        expectedIndex[1] = (byte) length;
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        System.arraycopy(digest, 0, expectedIndex, Safe.INDEX_ID_OFFSET, Safe.INDEX_ID_LENGTH);

        byte[] index = card.create("seed", null, null, data, false);
        Assertions.assertArrayEquals(expectedIndex, index);
        assertData(card, index, data);
        card.success(0x35, fields("index", index));
        card.create(index, null, null, data, false);
        assertData(card, index, data);
      }
    }
  }

  @Test
  public void reinstallingMonoidPreservesIdentityAndRestoresEncryptedItems() throws Exception {
    try (Card card = new Card(true)) {
      byte[] sender = card.publicKey();
      byte[] identityId = card.safeId();
      byte[] plainIndex = customIndex(50);
      card.create(plainIndex, new byte[] { 4, 5 }, "restored", sequence(64), false);
      byte[] keyIndex = card.create("secp256k1", null, null, SECP256K1_KEY, true);
      assertECDSAKeyAndSimulatorLimitation(card, keyIndex);
      card.authenticate(true);
      Transfer plain = card.export(plainIndex, sender);
      Transfer secret = card.export(keyIndex, sender);

      card.reinstallMonoid();
      Assertions.assertArrayEquals(sender, card.publicKey());
      Assertions.assertArrayEquals(identityId, card.safeId());
      Assertions.assertEquals(0, itemCount(card));
      card.success(0x37, plain.request(sender));
      card.success(0x37, secret.request(sender));
      assertData(card, plainIndex, sequence(64));
      assertMetadata(card, plainIndex, new byte[] { 4, 5 }, "restored", false);
      assertError(card.transmit(0x32, fields("index", keyIndex)), "ACCESS_DENIED");
      assertECDSAKeyAndSimulatorLimitation(card, keyIndex);
    }
  }

  private static void assertECDSAKeyAndSimulatorLimitation(Card card, byte[] index) {
    byte[] publicKey = card
      .success(0x40, fields("index", index, "type", "secp256k1"))
      .bytes("publicKey");
    X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
    Assertions.assertArrayEquals(
      curve.getG().multiply(new BigInteger(1, SECP256K1_KEY)).getEncoded(true),
      publicKey
    );
    // jCardSim returns null from Signature.OneShot.open for PLAIN ECDSA.
    // This verifies the exact unsupported path, not a successful ECDSA signature.
    assertCryptoError(
      card.transmit(
        0x41,
        fields("index", index, "type", "secp256k1", "cipher", "ecdsa", "digest", DIGEST)
      ),
      CryptoException.NO_SUCH_ALGORITHM
    );
  }

  private static void verifyED25519(Card card, byte[] index) throws Exception {
    byte[] message = { 0x72 };
    byte[] publicKey = card
      .success(0x40, fields("index", index, "type", "ed25519"))
      .bytes("publicKey");
    byte[] signature = card
      .success(
        0x41,
        fields("index", index, "type", "ed25519", "cipher", "ed25519", "message", message)
      )
      .bytes("signature");
    Assertions.assertEquals(64, signature.length);

    Process process = new ProcessBuilder(
      "node",
      "-e",
      "const c = require('node:crypto'); " +
      "const [seed, pub, msg, sig] = process.argv.slice(1).map(x => Buffer.from(x, 'hex')); " +
      "const key = c.createPrivateKey({key: Buffer.concat([" +
      "Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8'}); " +
      "const publicKey = c.createPublicKey(key); " +
      "const expected = publicKey.export({format: 'der', type: 'spki'}).subarray(-32); " +
      "process.exit(expected.equals(pub) && c.sign(null, msg, key).equals(sig) && " +
      "c.verify(null, msg, publicKey, sig) ? 0 : 1);",
      Hex.toHexString(ED25519_KEY),
      Hex.toHexString(publicKey),
      Hex.toHexString(message),
      Hex.toHexString(signature)
    )
      .inheritIO()
      .start();
    Assertions.assertEquals(0, process.waitFor());
  }

  static void assertData(Card card, byte[] index, byte[] data) {
    Result result = card.success(0x32, fields("index", index));
    Assertions.assertEquals(1, result.size());
    Assertions.assertArrayEquals(data, result.bytes("data"));
  }

  static void assertMetadata(Card card, byte[] index, byte[] key, String alias, boolean secret) {
    Result result = card.success(0x31, fields("index", index));
    Assertions.assertEquals(1 + (key == null ? 0 : 1) + (alias == null ? 0 : 1), result.size());
    CBORBufferReader reader = result.reader();
    Assertions.assertEquals(secret, reader.requireKey(bytes("secret")).bool());
    Assertions.assertEquals(key != null, reader.key(bytes("key")));
    if (key != null) {
      Assertions.assertArrayEquals(key, reader.bytes());
    }
    Assertions.assertEquals(alias != null, reader.key(bytes("alias")));
    if (alias != null) {
      Assertions.assertArrayEquals(bytes(alias), reader.text());
    }
  }

  private static void assertListedSecret(Card card, byte[] index, boolean secret) {
    Result result = card.success(0x30, fields());
    short count = result.reader().requireKey(bytes("items")).array();
    for (short item = 0; item < count; item++) {
      CBORBufferReader reader = result.reader();
      reader.requireKey(bytes("items")).array();
      Assertions.assertTrue(reader.index(item));
      reader.map();
      if (Arrays.equals(index, reader.requireKey(bytes("index")).bytes())) {
        Assertions.assertEquals(secret, reader.requireKey(bytes("secret")).bool());
        return;
      }
    }
    Assertions.fail("Item missing from List");
  }

  private static int itemCount(Card card) {
    return card.success(0x30, fields()).reader().requireKey(bytes("items")).array();
  }

  private static void assertAbsent(Card card, byte[] index) {
    assertError(card.transmit(0x31, fields("index", index)), "NOT_FOUND");
  }

  static void assertError(Result result, String code) {
    Assertions.assertEquals(0x9000, result.status);
    CBORBufferReader reader = result.reader();
    reader.requireKey(bytes("error")).map();
    Assertions.assertArrayEquals(bytes(code), reader.requireKey(bytes("code")).text());
  }

  static void assertCryptoRejected(Result result) {
    assertCryptoError(result, CryptoException.ILLEGAL_VALUE);
  }

  private static void assertCryptoError(Result result, short reason) {
    assertError(result, "INTERNAL");
    CBORBufferReader reader = result.reader();
    reader.requireKey(bytes("error")).map();
    Assertions.assertArrayEquals(
      bytes("CryptoException"),
      reader.requireKey(bytes("exception")).text()
    );
    Assertions.assertEquals(reason, reader.requireKey(bytes("reason")).integer());
  }

  static byte[] customIndex(int identifier) {
    byte[] index = new byte[Safe.INDEX_LENGTH];
    index[0] = 0x10;
    index[index.length - 2] = (byte) (identifier >> 8);
    index[index.length - 1] = (byte) identifier;
    return index;
  }

  static byte[] sequence(int length) {
    byte[] data = new byte[length];
    for (int index = 0; index < length; index++) {
      data[index] = (byte) index;
    }
    return data;
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  static Map<String, Object> fields(Object... entries) {
    Map<String, Object> result = new LinkedHashMap<>();
    for (int index = 0; index < entries.length; index += 2) {
      result.put((String) entries[index], entries[index + 1]);
    }
    return result;
  }

  private static byte[] encode(Map<String, Object> fields) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) fields.size());
    for (Map.Entry<String, Object> field : fields.entrySet()) {
      writer.text(bytes(field.getKey()));
      Object value = field.getValue();
      if (value instanceof byte[]) {
        writer.bytes((byte[]) value);
      } else if (value instanceof byte[][]) {
        byte[][] values = (byte[][]) value;
        writer.array((short) values.length);
        for (byte[] entry : values) {
          writer.bytes(entry);
        }
      } else if (value instanceof String) {
        writer.text(bytes((String) value));
      } else if (value instanceof Boolean) {
        writer.bool((Boolean) value);
      } else {
        writer.integer(((Number) value).shortValue());
      }
    }
    // Retain host arrays across reset and when the active simulator changes.
    return writer.getDataBuffer().clone();
  }

  static class Result {

    final byte[] data;
    final int status;
    final int requestFrames;
    final int responseFrames;

    Result(byte[] data, int status, int requestFrames, int responseFrames) {
      this.data = data;
      this.status = status;
      this.requestFrames = requestFrames;
      this.responseFrames = responseFrames;
    }

    CBORBufferReader reader() {
      CBORBufferReader reader = new CBORBufferReader(data);
      reader.map();
      return reader;
    }

    int size() {
      return new CBORBufferReader(data).map();
    }

    byte[] bytes(String field) {
      return reader().requireKey(MonoidItemTransferTest.bytes(field)).bytes().clone();
    }

    void assertSuccess() {
      Assertions.assertEquals(0x9000, status);
      CBORBufferReader reader = reader();
      if (reader.key(MonoidItemTransferTest.bytes("error"))) {
        reader.map();
        String detail = new String(
          reader.requireKey(MonoidItemTransferTest.bytes("code")).text(),
          StandardCharsets.US_ASCII
        );
        if (reader.key(MonoidItemTransferTest.bytes("exception"))) {
          detail += ": " + new String(reader.text(), StandardCharsets.US_ASCII);
        }
        if (reader.key(MonoidItemTransferTest.bytes("reason"))) {
          detail += " (reason " + reader.integer() + ")";
        }
        Assertions.fail(detail);
      }
    }
  }

  private static class Transfer {

    final byte[] index;
    final byte[] key;
    final String alias;
    final byte[] data;
    final int responseFrames;

    Transfer(byte[] index, Result result) {
      this.index = index.clone();
      CBORBufferReader reader = result.reader();
      key = reader.key(bytes("key")) ? reader.bytes().clone() : null;
      alias = reader.key(bytes("alias")) ? new String(reader.text(), StandardCharsets.UTF_8) : null;
      data = result.bytes("data");
      responseFrames = result.responseFrames;
      Assertions.assertEquals(1 + (key == null ? 0 : 1) + (alias == null ? 0 : 1), result.size());
    }

    Map<String, Object> request(byte[] senderPublicKey) {
      Map<String, Object> request = fields("index", index, "senderPublicKey", senderPublicKey);
      if (key != null) {
        request.put("key", key);
      }
      if (alias != null) {
        request.put("alias", alias);
      }
      request.put("data", data);
      return request;
    }
  }

  static class Card implements AutoCloseable {

    final CardSimulator simulator;
    private boolean monoidLoaded;
    private boolean monoidInstalled;

    Card(boolean installMonoid) {
      System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
      System.setProperty("com.licel.jcardsim.sign.dsasigner.computedhash", "1");
      System.setProperty("com.licel.jcardsim.bouncycastle.rsa.allow_unsafe_mod", "true");
      simulator = new CardSimulator(new ShareableSimulatorRuntime());
      simulator.installApplet(IDENTITY_AID, MonoidIdentityApplet.class);

      if (installMonoid) {
        installMonoid();
      }
    }

    void installMonoid() {
      resetAppletState();
      if (monoidLoaded) {
        simulator.createApplet(MONOID_AID, new byte[0], (short) 0, (byte) 0);
      } else {
        simulator.installApplet(MONOID_AID, MonoidApplet.class);
        monoidLoaded = true;
      }
      monoidInstalled = true;
      initializePINs();
    }

    private void initializePINs() {
      Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
      success(0x22, fields("pin", SAFE_PIN, "safe", true));
      authenticate(true);
      success(0x22, fields("pin", ACCESS_PIN));
      authenticate(false);
    }

    byte[] bootstrapPublicKey() {
      simulator.installApplet(IDENTITY_CALLER_AID, IdentityCallerApplet.class);
      Assertions.assertTrue(simulator.selectApplet(IDENTITY_CALLER_AID));
      ResponseAPDU acquired = simulator.transmitCommand(
        new CommandAPDU(
          0,
          IdentityCallerApplet.GET_SHAREABLE,
          0,
          0,
          AppletTest.aidBytes(IDENTITY_AID)
        )
      );
      Assertions.assertEquals(0x9000, acquired.getSW());
      ResponseAPDU response = simulator.transmitCommand(
        new CommandAPDU(0, IdentityCallerApplet.GET_PUBLIC_KEY, 0, 0)
      );
      Assertions.assertEquals(0x9000, response.getSW());
      byte[] publicKey = response.getData();
      Assertions.assertEquals(65, publicKey.length);
      simulator.deleteApplet(IDENTITY_CALLER_AID);
      return publicKey;
    }

    byte[] publicKey() {
      CBORBufferReader reader = success(0x20, fields()).reader();
      return reader.requireKey(bytes("publicKey")).bytes().clone();
    }

    byte[] safeId() {
      CBORBufferReader reader = success(0x20, fields()).reader();
      return reader.requireKey(bytes("id")).bytes().clone();
    }

    void authenticate(boolean safe) {
      success(0x21, safe ? fields("pin", SAFE_PIN, "safe", true) : fields("pin", ACCESS_PIN));
    }

    void reset() {
      simulator.reset();
      Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    }

    void reinstallMonoid() {
      Assertions.assertTrue(simulator.selectApplet(IDENTITY_AID));
      simulator.deleteApplet(MONOID_AID);

      resetAppletState();
      // jCardSim retains the loaded classes when deleting instances.
      simulator.createApplet(MONOID_AID, new byte[0], (short) 0, (byte) 0);
      initializePINs();
    }

    void uninstallMonoid() {
      if (monoidInstalled) {
        simulator.deleteApplet(MONOID_AID);
        monoidInstalled = false;
        resetAppletState();
      }
    }

    byte[] create(Object selector, byte[] key, String alias, byte[] data, Boolean secret) {
      Map<String, Object> request = fields(
        "data",
        data,
        selector instanceof String ? "type" : "index",
        selector
      );
      if (key != null) {
        request.put("key", key);
      }
      if (alias != null) {
        request.put("alias", alias);
      }
      if (secret != null) {
        request.put("secret", secret);
      }
      return success(0x34, request).bytes("index");
    }

    Transfer export(byte[] index, byte[] recipientPublicKey) {
      return new Transfer(
        index,
        success(0x36, fields("index", index, "recipientPublicKey", recipientPublicKey))
      );
    }

    Result success(int instruction, Map<String, Object> request) {
      Result result = transmit(instruction, request);
      result.assertSuccess();
      return result;
    }

    Result transmit(int instruction, Map<String, Object> request) {
      return transmit(instruction, request, 255);
    }

    Result transmit(int instruction, Map<String, Object> request, int frameLength) {
      byte[] data = encode(request);
      ResponseAPDU response = null;
      int requestFrames = 0;
      for (int offset = 0; offset < data.length; offset += frameLength) {
        int end = Math.min(data.length, offset + frameLength);
        boolean last = end == data.length;
        int cla = offset == 0 ? (last ? 0 : 0x90) : (last ? 0xA0 : 0xB0);
        response = simulator.transmitCommand(
          new CommandAPDU(cla, instruction, 0, 0, Arrays.copyOfRange(data, offset, end))
        );
        requestFrames++;
        if (!last) {
          Assertions.assertEquals(0x9000, response.getSW());
          Assertions.assertEquals(0, response.getData().length);
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
        response = simulator.transmitCommand(
          new CommandAPDU(0, 0xC0, 0, 0, response.getSW2() == 0 ? 256 : response.getSW2())
        );
      }
    }

    private static void resetAppletState() {
      MonoidApplet.safe = null;
      MonoidApplet.keystore = null;
    }

    @Override
    public void close() {
      uninstallMonoid();
      simulator.deleteApplet(IDENTITY_AID);
    }
  }
}
