package tests;

import static tests.MonoidItemTransferTest.assertCryptoRejected;
import static tests.MonoidItemTransferTest.assertData;
import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.assertISOError;
import static tests.MonoidItemTransferTest.customIndex;
import static tests.MonoidItemTransferTest.fields;
import static tests.MonoidItemTransferTest.sequence;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

public class MonoidAuthorityBundleTest {

  private static final byte[] ROOT = sequence(32);

  @Test
  public void authorityEnrollmentRequiresSecretAuthorizationAndSurvivesPowerReset()
    throws Exception {
    AuthorityBundleIssuer issuer = new AuthorityBundleIssuer();

    for (boolean allowPeerExtension : new boolean[] { false, true }) {
      try (Card card = new Card(true, issuer.installationParameters())) {
        Map<String, Object> request = enrollment(
          issuer,
          card.publicKey(),
          ROOT,
          allowPeerExtension
        );

        card.reset();
        assertError(card.transmit(0x24, request), "UNAUTHORIZED");

        card.authenticate(false);
        assertError(card.transmit(0x24, request), "ACCESS_DENIED");
        assertNoBundle(card);

        card.authenticate(true);
        Assertions.assertArrayEquals(hash(ROOT), card.success(0x24, request).bytes("bundle"));

        card.reset();
        card.authenticate(true);
        Assertions.assertArrayEquals(hash(ROOT), card.success(0x24, request).bytes("bundle"));
      }
    }
  }

  @Test
  public void onlyTheInstalledAuthorityCanEnrollAndTheSenderMustProveItsPrivateKey()
    throws Exception {
    AuthorityBundleIssuer trusted = new AuthorityBundleIssuer();
    AuthorityBundleIssuer other = new AuthorityBundleIssuer();

    try (Card card = new Card(true)) {
      card.authenticate(true);

      assertISOError(
        card.transmit(0x24, enrollment(trusted, card.publicKey(), ROOT, false)),
        0x6985
      );
      assertNoBundle(card);
    }

    try (Card card = new Card(true, trusted.installationParameters())) {
      card.authenticate(true);

      Map<String, Object> untrusted = enrollment(other, card.publicKey(), ROOT, false);

      assertISOError(card.transmit(0x24, untrusted), 0x6985);

      untrusted.put("publicKey", trusted.publicKey());
      assertCryptoRejected(card.transmit(0x24, untrusted));
      assertNoBundle(card);

      card.success(0x24, enrollment(trusted, card.publicKey(), ROOT, false));
    }
  }

  @Test
  public void flagsCountVersionAndAuthenticationTagAreBoundToTheEnrollment() throws Exception {
    AuthorityBundleIssuer issuer = new AuthorityBundleIssuer();

    try (Card card = new Card(true, issuer.installationParameters())) {
      card.authenticate(true);
      byte[] data = issuer.issue(card.publicKey(), ROOT, false);

      for (int offset : new int[] { 0, 1, 2, 3, data.length - 1 }) {
        byte[] tampered = data.clone();
        tampered[offset] ^= 1;

        assertCryptoRejected(
          card.transmit(0x24, fields("publicKey", issuer.publicKey(), "data", tampered))
        );
        assertNoBundle(card);
      }

      byte[] unknownFlags = data.clone();
      unknownFlags[1] |= 4;

      assertCryptoRejected(
        card.transmit(0x24, fields("publicKey", issuer.publicKey(), "data", unknownFlags))
      );
      assertNoBundle(card);

      card.success(0x24, fields("publicKey", issuer.publicKey(), "data", data));
    }
  }

  @Test
  public void enrollmentIsBoundToTheRecipientEvenWhenTheHeaderIsReplaced() throws Exception {
    AuthorityBundleIssuer issuer = new AuthorityBundleIssuer();

    try (Card other = new Card(false, issuer.installationParameters())) {
      byte[] otherKey = other.bootstrapPublicKey();

      try (Card card = new Card(true, issuer.installationParameters())) {
        card.authenticate(true);
        byte[] data = issuer.issue(otherKey, ROOT, false);

        assertISOError(
          card.transmit(0x24, fields("publicKey", issuer.publicKey(), "data", data)),
          0x6985
        );

        System.arraycopy(card.publicKey(), 0, data, 4, 65);
        assertCryptoRejected(
          card.transmit(0x24, fields("publicKey", issuer.publicKey(), "data", data))
        );
        assertNoBundle(card);
      }
    }
  }

  @Test
  public void repeatedJoinCannotReplaceTheRootOrChangePeerExtensionPolicy() throws Exception {
    AuthorityBundleIssuer issuer = new AuthorityBundleIssuer();

    for (boolean allowPeerExtension : new boolean[] { false, true }) {
      try (Card card = new Card(true, issuer.installationParameters())) {
        card.authenticate(true);
        byte[] recipient = card.publicKey();

        card.success(0x24, enrollment(issuer, recipient, ROOT, allowPeerExtension));

        byte[] otherRoot = ROOT.clone();
        otherRoot[0] ^= 1;

        for (Map<String, Object> conflicting : Arrays.asList(
          enrollment(issuer, recipient, otherRoot, allowPeerExtension),
          enrollment(issuer, recipient, ROOT, !allowPeerExtension)
        )) {
          assertISOError(card.transmit(0x24, conflicting), 0x6985);
          Assertions.assertArrayEquals(hash(ROOT), card.success(0x20, fields()).bytes("bundle"));
        }

        card.success(0x24, enrollment(issuer, recipient, ROOT, allowPeerExtension));
      }
    }
  }

  @Test
  public void disabledPolicyRejectsBothPeerExtensionCommands() throws Exception {
    AuthorityBundleIssuer issuer = new AuthorityBundleIssuer();

    try (
      Card initiator = new Card(false, issuer.installationParameters());
      Card card = new Card(false, issuer.installationParameters());
      Card target = new Card(false);
    ) {
      byte[] initiatorKey = initiator.bootstrapPublicKey();
      byte[] cardKey = card.bootstrapPublicKey();
      byte[] targetKey = target.bootstrapPublicKey();

      initiator.installMonoid();
      initiator.authenticate(true);
      initiator.success(0x24, enrollment(issuer, initiatorKey, ROOT, true));

      byte[] extension = initiator.success(0x25, fields("publicKey", targetKey)).bytes("data");

      initiator.uninstallMonoid();

      // Deliberately inconsistent issuer policy: a valid same-root proof must not override local policy.
      card.installMonoid();
      card.authenticate(true);
      card.success(0x24, enrollment(issuer, cardKey, ROOT, false));

      assertISOError(card.transmit(0x25, fields("publicKey", targetKey)), 0x6985);
      assertISOError(card.transmit(0x26, fields("data", extension)), 0x6985);
      Assertions.assertArrayEquals(hash(ROOT), card.success(0x20, fields()).bytes("bundle"));
    }
  }

  @Test
  public void authorityCannotReplaceAManuallyCreatedBundle() throws Exception {
    AuthorityBundleIssuer issuer = new AuthorityBundleIssuer();

    try (Card peer = new Card(false)) {
      byte[] peerKey = peer.bootstrapPublicKey();

      try (Card card = new Card(true, issuer.installationParameters())) {
        byte[] index = customIndex(244);
        byte[] data = sequence(64);

        card.create(index, null, null, data, false);

        card.authenticate(true);
        byte[] bundle = card
          .success(0x23, fields("publicKeys", new byte[][] { peerKey }))
          .bytes("bundle");

        Assertions.assertFalse(Arrays.equals(hash(ROOT), bundle));
        assertISOError(
          card.transmit(0x24, enrollment(issuer, card.publicKey(), ROOT, true)),
          0x6985
        );
        Assertions.assertArrayEquals(bundle, card.success(0x20, fields()).bytes("bundle"));
        assertData(card, index, data);
      }
    }
  }

  @Test
  public void authorityCanAdmitAnotherCardWhenPeerExtensionIsDisabled() throws Exception {
    AuthorityBundleIssuer issuer = new AuthorityBundleIssuer();

    try (
      Card first = new Card(false, issuer.installationParameters());
      Card second = new Card(false, issuer.installationParameters());
    ) {
      byte[] firstKey = first.bootstrapPublicKey();
      byte[] secondKey = second.bootstrapPublicKey();

      byte[] index = customIndex(243);
      byte[] data = sequence(384);

      first.installMonoid();
      first.authenticate(true);
      first.success(0x24, enrollment(issuer, firstKey, ROOT, false));

      first.create(index, null, null, data, false);
      byte[] envelope = first.success(0x36, fields("index", index)).bytes("data");

      first.uninstallMonoid();

      second.installMonoid();
      second.authenticate(true);
      second.success(0x24, enrollment(issuer, secondKey, ROOT, false));

      second.success(0x37, fields("index", index, "data", envelope));

      assertData(second, index, data);
      assertISOError(second.transmit(0x25, fields("publicKey", firstKey)), 0x6985);
    }
  }

  @Test
  public void independentlyIssuedMembersCanExtendAndTransferWithoutSnapshotSynchronization()
    throws Exception {
    AuthorityBundleIssuer issuer = new AuthorityBundleIssuer();

    // Monoid statics are JVM-wide; retain Identity while installing one Monoid at a time.
    try (
      Card first = new Card(false, issuer.installationParameters());
      Card second = new Card(false, issuer.installationParameters());
      Card third = new Card(false);
    ) {
      byte[] firstKey = first.bootstrapPublicKey();
      byte[] secondKey = second.bootstrapPublicKey();
      byte[] thirdKey = third.bootstrapPublicKey();

      byte[] firstIndex = customIndex(240);
      byte[] secondIndex = customIndex(241);
      byte[] thirdIndex = customIndex(242);

      byte[] data = sequence(384);

      first.installMonoid();
      first.authenticate(true);
      first.success(0x24, enrollment(issuer, firstKey, ROOT, true));

      first.create(firstIndex, null, null, data, false);
      byte[] firstEnvelope = first.success(0x36, fields("index", firstIndex)).bytes("data");

      byte[] extension = first.success(0x25, fields("publicKey", thirdKey)).bytes("data");

      first.uninstallMonoid();

      second.installMonoid();
      second.authenticate(true);
      second.success(0x24, enrollment(issuer, secondKey, ROOT, true));

      second.success(0x37, fields("index", firstIndex, "data", firstEnvelope));
      assertData(second, firstIndex, data);

      second.create(secondIndex, null, null, data, false);
      byte[] secondEnvelope = second.success(0x36, fields("index", secondIndex)).bytes("data");

      Result approval = second.success(0x26, fields("data", extension));

      Assertions.assertArrayEquals(secondKey, approval.bytes("publicKey"));

      byte[] thirdEnrollment = approval.bytes("data");

      Assertions.assertEquals(1, thirdEnrollment[1]);
      Assertions.assertEquals(2, ((thirdEnrollment[2] & 0xFF) << 8) | (thirdEnrollment[3] & 0xFF));

      second.uninstallMonoid();

      third.installMonoid();
      third.authenticate(true);

      Assertions.assertArrayEquals(
        hash(ROOT),
        third.success(0x24, fields("publicKey", secondKey, "data", thirdEnrollment)).bytes("bundle")
      );
      Assertions.assertEquals(1, third.success(0x25, fields("publicKey", firstKey)).size());

      third.success(0x37, fields("index", firstIndex, "data", firstEnvelope));
      third.success(0x37, fields("index", secondIndex, "data", secondEnvelope));

      assertData(third, firstIndex, data);
      assertData(third, secondIndex, data);

      third.create(thirdIndex, null, null, data, false);
      byte[] thirdEnvelope = third.success(0x36, fields("index", thirdIndex)).bytes("data");

      third.uninstallMonoid();

      first.installMonoid();
      first.authenticate(true);
      first.success(0x37, fields("index", thirdIndex, "data", thirdEnvelope));

      assertData(first, thirdIndex, data);
    }
  }

  @Test
  public void resetPreservesAuthorityButRejectsPacketsForTheFormerIdentity() throws Exception {
    AuthorityBundleIssuer issuer = new AuthorityBundleIssuer();

    try (Card card = new Card(true, issuer.installationParameters())) {
      byte[] id = card.safeId();
      byte[] oldKey = card.publicKey();
      Map<String, Object> request = enrollment(issuer, oldKey, ROOT, false);

      card.authenticate(true);
      card.success(0x24, request);

      card.success(0xFF, fields());

      Assertions.assertArrayEquals(id, card.safeId());
      Assertions.assertFalse(Arrays.equals(oldKey, card.publicKey()));

      card.success(0x22, fields("pin", "888888", "secret", true));
      card.authenticate(true);

      assertISOError(card.transmit(0x24, request), 0x6985);
      assertNoBundle(card);

      card.success(0x24, enrollment(issuer, card.publicKey(), ROOT, false));
    }
  }

  private static Map<String, Object> enrollment(
    AuthorityBundleIssuer issuer,
    byte[] recipient,
    byte[] root,
    boolean allowPeerExtension
  ) throws Exception {
    return fields(
      "publicKey",
      issuer.publicKey(),
      "data",
      issuer.issue(recipient, root, allowPeerExtension)
    );
  }

  private static byte[] hash(byte[] root) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(root);
  }

  private static void assertNoBundle(Card card) {
    Assertions.assertFalse(
      card
        .success(0x20, fields())
        .reader()
        .requireKey("bundle".getBytes(StandardCharsets.US_ASCII))
        .bool()
    );
  }
}
