package tests;

import static tests.MonoidItemTransferTest.fields;
import static tests.MonoidItemTransferTest.sequence;
import static tests.MonoidSecurityKeyTest.assertSignature;
import static tests.MonoidSecurityKeyTest.assertion;
import static tests.MonoidSecurityKeyTest.descriptor;
import static tests.MonoidSecurityKeyTest.index;
import static tests.MonoidSecurityKeyTest.make;
import static tests.MonoidSecurityKeyTest.mapValue;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.utils.AIDUtil;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;
import monoidlib.CBORBufferReader;
import monoidsecuritykey.CTAP;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidSecurityKeyTest.Fixture;
import tests.MonoidSecurityKeyTest.Registration;

public class SecurityKeyScopeTest {

  private static final String RP = "example.com";
  private static final byte[] DOMAIN = bytes("security-key");
  private static final byte[] OTHER_DOMAIN = bytes("another-domain");

  @Test
  public void domainSwitchingKeepsReplacementExclusionAndLookupInsideTheSelectedScope()
    throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Registration original = fixture.register(RP, 1, true, null);
      byte[] originalScope = scope(fixture, original);

      grant(fixture, fixture.seedIndex, OTHER_DOMAIN);
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, original.id));
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, null));

      // A valid credential in the other scope neither excludes nor gets replaced by this one.
      Map<Object, Object> request = make(RP, 1, true);
      request.put(5, Arrays.asList(descriptor(original.id)));
      Registration other = new Registration(fixture.success(0x01, request), RP);
      other.verify();
      Assertions.assertFalse(Arrays.equals(originalScope, scope(fixture, other)));
      assertStored(fixture, original, other);

      grant(fixture, fixture.seedIndex, DOMAIN);
      assertSignature(fixture.success(0x02, assertion(RP, original.id)), original, 1);
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, other.id));

      request.put(5, Arrays.asList(descriptor(other.id)));
      Registration replacement = new Registration(fixture.success(0x01, request), RP);
      replacement.verify();
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, original.id));
      assertStored(fixture, replacement, other);

      fixture.manage();
      MonoidItemTransferTest.assertError(
        fixture.card.transmit(0x31, fields("index", index(original.id))),
        "NOT_FOUND"
      );

      grant(fixture, fixture.seedIndex, OTHER_DOMAIN);
      assertSignature(fixture.success(0x02, assertion(RP, other.id)), other, 1);
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, replacement.id));
    }
  }

  @Test
  public void replacingSeedBytesAtTheSameIndexChangesScopeAndRestoringThemRestoresUse()
    throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Registration original = fixture.register(RP, 1, true, null);
      byte[] originalScope = scope(fixture, original);
      byte[] changedSeed = sequence(64);
      changedSeed[0] ^= 1;

      replaceSeed(fixture, changedSeed);
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, original.id));
      Registration changed = fixture.register(RP, 1, true, null);
      Assertions.assertFalse(Arrays.equals(originalScope, scope(fixture, changed)));
      assertStored(fixture, original, changed);

      replaceSeed(fixture, sequence(64));
      assertSignature(fixture.success(0x02, assertion(RP, original.id)), original, 1);
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, changed.id));

      replaceSeed(fixture, changedSeed);
      assertSignature(fixture.success(0x02, assertion(RP, changed.id)), changed, 1);
    }
  }

  @Test
  public void discoveryBeyondTheBoundedCacheNeverMixesScopesAndReselectionEndsPendingResults()
    throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Registration[] original = registerAccounts(fixture);
      grant(fixture, fixture.seedIndex, OTHER_DOMAIN);
      Registration[] other = registerAccounts(fixture);
      assertDiscovered(fixture, other);

      grant(fixture, fixture.seedIndex, DOMAIN);
      assertDiscovered(fixture, original);
      Registration previous = original[0];
      original[0] = fixture.register(RP, 1, true, null);
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, previous.id));
      assertDiscovered(fixture, original);

      Assertions.assertEquals(original.length, fixture.success(0x02, assertion(RP, null)).get(5));
      grant(fixture, fixture.seedIndex, OTHER_DOMAIN);
      fixture.error(CTAP.NOT_ALLOWED, 0x08, null);
      assertDiscovered(fixture, other);
    }
  }

  @Test
  public void scopeIsStableAcrossCardsAndSeedIndicesAndMatchesThePublicDerivation()
    throws Exception {
    byte[] expected;

    // Applet static fields are JVM-wide, so finish one simulated card before creating the next.
    try (Fixture first = new Fixture(true)) {
      Registration registration = first.register(RP, 1, true, null);
      expected = scope(first, registration);
      Assertions.assertArrayEquals(expectedScope(first, DOMAIN), expected);
    }

    try (Fixture second = new Fixture(true)) {
      Registration registration = second.register(RP, 2, true, null);
      Assertions.assertArrayEquals(expected, scope(second, registration));

      second.manage();
      byte[] otherSeed = sequence(64);
      otherSeed[0] ^= 1;
      byte[] anotherIndex = second.card.create("seed", null, null, otherSeed, true);
      second.card.success(0x33, fields("index", anotherIndex, "data", sequence(64)));
      grant(second, anotherIndex, DOMAIN);

      assertSignature(second.success(0x02, assertion(RP, registration.id)), registration, 1);
      Registration another = second.register(RP, 3, true, null);
      Assertions.assertArrayEquals(expected, scope(second, another));
    }
  }

  private static Registration[] registerAccounts(Fixture fixture) throws Exception {
    Registration[] registrations = new Registration[6];

    for (int position = 0; position < registrations.length; position++) {
      registrations[position] = fixture.register(RP, position + 1, true, null);
    }

    return registrations;
  }

  private static void assertDiscovered(Fixture fixture, Registration[] expected) throws Exception {
    Map<Object, Object> response = fixture.success(0x02, assertion(RP, null));
    Assertions.assertEquals(expected.length, response.get(5));
    boolean[] seen = new boolean[expected.length];

    for (int position = 0; position < expected.length; position++) {
      if (position > 0) {
        response = fixture.success(0x08, null);
      }

      byte[] id = (byte[]) mapValue(response.get(1)).get("id");
      int account = 0;

      while (account < expected.length && !Arrays.equals(id, expected[account].id)) {
        account++;
      }

      Assertions.assertTrue(account < expected.length, "Credential belongs to another scope");
      Assertions.assertFalse(seen[account], "Duplicate credential");
      seen[account] = true;
      assertSignature(response, expected[account], 1);
    }

    fixture.error(CTAP.NOT_ALLOWED, 0x08, null);
  }

  private static void grant(Fixture fixture, byte[] seedIndex, byte[] domain) {
    fixture.manage();
    MonoidAppletGrantTest.success(
      fixture.card,
      0x51,
      fields(
        "aid",
        AppletTest.aidBytes(AIDUtil.create("a0000006472f0001")),
        "types",
        Arrays.asList(Arrays.asList((short) 0xF101, true)),
        "seed",
        fields("index", seedIndex, "domain", domain)
      )
    );
    fixture.select();
  }

  private static void replaceSeed(Fixture fixture, byte[] seed) {
    fixture.manage();
    fixture.card.success(0x33, fields("index", fixture.seedIndex, "data", seed));
    fixture.select();
  }

  private static void assertStored(Fixture fixture, Registration... registrations) {
    fixture.manage();

    for (Registration registration : registrations) {
      fixture.card.success(0x31, fields("index", index(registration.id)));
    }

    fixture.select();
  }

  private static byte[] scope(Fixture fixture, Registration registration) throws Exception {
    fixture.manage();
    byte[] index = index(registration.id);
    byte[] metadata = fixture.card.success(0x31, fields("index", index)).bytes("metadata");
    byte[] data = fixture.card.success(0x32, fields("index", index)).bytes("data");
    CBORBufferReader reader = new CBORBufferReader(data);
    short count = reader.map();
    byte[] scope = null;

    for (short field = 0; field < count; field++) {
      if (reader.integer() == 10) {
        scope = reader.bytes().clone();
      } else {
        reader.skip();
      }
    }

    Assertions.assertNotNull(scope);
    Assertions.assertEquals(32, scope.length);
    Assertions.assertEquals(64, metadata.length);
    Assertions.assertArrayEquals(scope, Arrays.copyOf(metadata, 32));
    Assertions.assertArrayEquals(
      MessageDigest.getInstance("SHA-256").digest(bytes(RP)),
      Arrays.copyOfRange(metadata, 32, 64)
    );
    fixture.select();

    return scope;
  }

  private static byte[] expectedScope(Fixture fixture, byte[] domain) throws Exception {
    byte[] prefix = bytes("monoid applet: ");
    byte[] purpose = bytes("monoid fido2 scope: ");
    byte[] context = new byte[prefix.length + 2 + domain.length + 78];
    System.arraycopy(prefix, 0, context, 0, prefix.length);
    context[prefix.length] = (byte) (domain.length >> 8);
    context[prefix.length + 1] = (byte) domain.length;
    System.arraycopy(domain, 0, context, prefix.length + 2, domain.length);
    System.arraycopy(purpose, 0, context, prefix.length + 2 + domain.length, purpose.length);
    fixture.manage();
    byte[] compressed = MonoidAppletGrantTest.success(
      fixture.card,
      0x40,
      fields(
        "index",
        fixture.seedIndex,
        "type",
        "seed",
        "derivation",
        fields("type", "monoid-001", "context", context)
      )
    ).bytes("publicKey");
    byte[] publicKey = SECNamedCurves.getByName("secp256r1")
      .getCurve()
      .decodePoint(compressed)
      .getEncoded(false);
    fixture.select();

    return MessageDigest.getInstance("SHA-256").digest(publicKey);
  }

  private static byte[] bytes(String text) {
    return text.getBytes(StandardCharsets.UTF_8);
  }
}
