package tests;

import static tests.MonoidItemTransferTest.fields;
import static tests.MonoidItemTransferTest.sequence;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javacard.framework.AID;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoidsecuritykey.CTAP;
import monoidsecuritykey.MonoidSecurityKeyApplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;

public class MonoidSecurityKeyTest {

  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );
  private static final AID FIDO_AID = AIDUtil.create("a0000006472f0001");
  private static final AID FIDO_APPLET_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SECURITY_KEY_APPLET_AID}}"
    "f06d6f6e6f69640301"
  );
  private static final String RP = "example.com";
  private static final byte[] CLIENT_DATA_HASH = sequence(32);
  private static final byte[] PIN = "314159".getBytes(StandardCharsets.UTF_8);

  @Test
  public void installationRegistersTheRequestedFidoInstanceInsteadOfTheModule() {
    try (Fixture fixture = new Fixture(false)) {
      Assertions.assertFalse(fixture.card.simulator.selectApplet(FIDO_APPLET_AID));
      fixture.select();
      Assertions.assertEquals(Arrays.asList("FIDO_2_0"), fixture.success(0x04, null).get(1));
    }
  }

  @Test
  public void installationWithoutAnInstanceAIDUsesTheModuleAID() {
    CardSimulator simulator = new CardSimulator();
    byte[] parameters = new byte[] { 0, 0, 0 };
    simulator.installApplet(
      FIDO_APPLET_AID,
      MonoidSecurityKeyApplet.class,
      parameters,
      (short) 0,
      (byte) parameters.length
    );
    try {
      Assertions.assertTrue(simulator.selectApplet(FIDO_APPLET_AID));
      Assertions.assertFalse(simulator.selectApplet(FIDO_AID));
    } finally {
      simulator.deleteApplet(FIDO_APPLET_AID);
    }
  }

  @Test
  public void selectionInfoAndRegistrationUseTheGrantedSeedWithoutAPDUPIN() throws Exception {
    try (Fixture fixture = new Fixture(false)) {
      Map<Object, Object> info = fixture.success(0x04, null);
      Assertions.assertEquals(Arrays.asList("FIDO_2_0"), info.get(1));
      Assertions.assertEquals(Arrays.asList(1), info.get(6));
      Assertions.assertEquals(1200, info.get(5));
      Map<Object, Object> options = mapValue(info.get(4));
      Assertions.assertEquals(true, options.get("rk"));
      Assertions.assertEquals(true, options.get("up"));
      Assertions.assertEquals(false, options.get("clientPin"));
      fixture.error(CTAP.OPERATION_DENIED, 0x01, make(RP, 1, false));
      fixture.grant(true);
      fixture.card.simulator.reset();
      fixture.select();
      Registration registration = fixture.register(RP, 1, false, null);
      registration.verify();
      Assertions.assertEquals(0x41, registration.authData[32]);
      Assertions.assertArrayEquals(new byte[4], Arrays.copyOfRange(registration.authData, 33, 37));
      Assertions.assertArrayEquals(new byte[16], Arrays.copyOfRange(registration.authData, 37, 53));
    }
  }

  @Test
  public void nonResidentAssertionChecksRPFullCredentialIdAndExclusionsWithoutARecord()
    throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Registration registration = fixture.register(RP, 1, false, null);
      fixture.manage();
      MonoidItemTransferTest.assertError(
        fixture.card.transmit(0x31, fields("index", index(registration.id))),
        "NOT_FOUND"
      );
      fixture.select();
      Map<Object, Object> request = assertion(RP, registration.id);
      Map<Object, Object> response = fixture.success(0x02, request);
      assertSignature(response, registration, 1);
      Assertions.assertFalse(response.containsKey(5));
      fixture.error(CTAP.NOT_ALLOWED, 0x08, null);
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion("other.example", registration.id));
      byte[] collision = registration.id.clone();
      collision[31] ^= 1;
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, collision));
      Map<Object, Object> excluded = make(RP, 2, false);
      excluded.put(5, Arrays.asList(descriptor(registration.id)));
      fixture.error(CTAP.CREDENTIAL_EXCLUDED, 0x01, excluded);
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, null));

      fixture.card.simulator.reset();
      fixture.select();
      assertSignature(fixture.success(0x02, request), registration, 1);
    }
  }

  @Test
  public void removingAStoredRecordRevokesItsCredentialId() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Registration registration = fixture.register(RP, 1, true, null);
      Map<Object, Object> request = assertion(RP, registration.id);
      assertSignature(fixture.success(0x02, request), registration, 1);

      fixture.manage();
      fixture.card.success(0x35, fields("index", index(registration.id)));
      fixture.select();
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, request);
    }
  }

  @Test
  public void allowListUsesTheFirstMatchButStillValidatesLaterDescriptors() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Registration first = fixture.register(RP, 1, false, null);
      Registration second = fixture.register(RP, 2, true, null);
      fixture.manage();
      fixture.card.success(0x33, fields("index", index(second.id), "data", new byte[] { 0 }));
      fixture.select();

      Map<Object, Object> request = assertion(RP, null);
      request.put(3, Arrays.asList(descriptor(first.id), descriptor(second.id)));
      assertSignature(fixture.success(0x02, request), first, 1);

      request.put(3, Arrays.asList(descriptor(first.id), map("type", "public-key")));
      fixture.error(CTAP.MISSING_PARAMETER, 0x02, request);
    }
  }

  @Test
  public void storedCredentialsMustMatchTheirIndexAndLookupKey() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Registration registration = fixture.register(RP, 1, true, null);
      fixture.manage();
      byte[] data = fixture.card
        .success(0x32, fields("index", index(registration.id)))
        .bytes("data");
      Map<Object, Object> stored = mapValue(decode(data));
      ((byte[]) stored.get(2))[0] ^= 1;
      fixture.card.success(0x33, fields("index", index(registration.id), "data", encode(stored)));
      fixture.select();
      fixture.error(CTAP.OTHER, 0x02, assertion(RP, registration.id));

      fixture.manage();
      stored = mapValue(decode(data));
      ((byte[]) stored.get(3))[0] ^= 1;
      fixture.card.success(0x33, fields("index", index(registration.id), "data", encode(stored)));
      fixture.select();
      fixture.error(CTAP.OTHER, 0x02, assertion(RP, registration.id));

      fixture.manage();
      fixture.card.success(0x33, fields("index", index(registration.id), "data", data));
      fixture.select();
      assertSignature(fixture.success(0x02, assertion(RP, registration.id)), registration, 1);
    }
  }

  @Test
  public void residentEnumerationSupportsNextAndSameAccountReplacement() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Registration first = fixture.register(RP, 1, true, null);
      Registration second = fixture.register(RP, 2, true, null);
      Map<Object, Object> response = fixture.success(0x02, assertion(RP, null));
      Assertions.assertEquals(2, response.get(5));
      byte[] selected = (byte[]) mapValue(response.get(1)).get("id");
      Registration selectedRegistration = Arrays.equals(selected, first.id) ? first : second;
      Registration remainingRegistration = selectedRegistration == first ? second : first;
      assertSignature(response, selectedRegistration, 1);
      Assertions.assertEquals(1, mapValue(response.get(4)).size());
      assertSignature(fixture.success(0x08, null), remainingRegistration, 1);
      fixture.error(CTAP.NOT_ALLOWED, 0x08, null);

      fixture.success(0x02, assertion(RP, null));
      fixture.success(0x04, null);
      fixture.error(CTAP.NOT_ALLOWED, 0x08, null);

      Registration replacement = fixture.register(RP, 1, true, null);
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, first.id));
      assertSignature(fixture.success(0x02, assertion(RP, replacement.id)), replacement, 1);
      Assertions.assertEquals(2, fixture.success(0x02, assertion(RP, null)).get(5));
    }
  }

  @Test
  public void fourResidentAccountsExcludeOtherRPAndSurviveReplacementAndReselection()
    throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Registration[] accounts = new Registration[4];
      for (int index = 0; index < accounts.length; index++) {
        accounts[index] = fixture.register(RP, index + 1, true, null);
        accounts[index].verify();
      }
      Registration other = fixture.register("other.example.com", 5, true, null);
      other.verify();

      for (int pass = 0; pass < 2; pass++) {
        if (pass == 1) {
          fixture.manage();
          fixture.select();
          Registration previous = accounts[1];
          accounts[1] = fixture.register(RP, 2, true, null);
          accounts[1].verify();
          fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, previous.id));
        }
        boolean[] seen = new boolean[accounts.length];
        Map<Object, Object> response = fixture.success(0x02, assertion(RP, null));
        Assertions.assertEquals(accounts.length, response.get(5));
        for (int position = 0; position < accounts.length; position++) {
          if (position != 0) {
            response = fixture.success(0x08, null);
            Assertions.assertFalse(response.containsKey(5));
          }
          byte[] id = (byte[]) mapValue(response.get(1)).get("id");
          int account = 0;
          while (account < accounts.length && !Arrays.equals(id, accounts[account].id)) {
            account++;
          }
          Assertions.assertTrue(account < accounts.length, "Unexpected RP/account");
          Assertions.assertFalse(seen[account], "Duplicate account");
          seen[account] = true;
          assertSignature(response, accounts[account], 1);
        }
        fixture.error(CTAP.NOT_ALLOWED, 0x08, null);
        assertSignature(fixture.success(0x02, assertion("other.example.com", other.id)), other, 1);
      }
    }
  }

  @Test
  public void managementDeletionAndRevocationCannotReusePendingAssertions() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Registration first = fixture.register(RP, 1, true, null);
      Registration second = fixture.register(RP, 2, true, null);
      Map<Object, Object> response = fixture.success(0x02, assertion(RP, null));
      byte[] selected = (byte[]) mapValue(response.get(1)).get("id");
      Registration selectedRegistration = Arrays.equals(selected, first.id) ? first : second;
      Registration remainingRegistration = selectedRegistration == first ? second : first;
      assertSignature(response, selectedRegistration, 1);

      fixture.manage();
      fixture.card.success(0x35, fields("index", index(remainingRegistration.id)));
      fixture.select();
      fixture.error(CTAP.NOT_ALLOWED, 0x08, null);
      assertSignature(fixture.success(0x02, assertion(RP, null)), selectedRegistration, 1);

      fixture.register(RP, 3, true, null);
      Assertions.assertEquals(2, fixture.success(0x02, assertion(RP, null)).get(5));
      fixture.manage();
      MonoidAppletGrantTest.success(
        fixture.card,
        0x52,
        fields("aid", AppletTest.aidBytes(FIDO_AID))
      );
      fixture.select();
      fixture.error(CTAP.NOT_ALLOWED, 0x08, null);
      fixture.error(CTAP.OPERATION_DENIED, 0x02, assertion(RP, selectedRegistration.id));
    }
  }

  @Test
  public void clientPINEnforcesRegistrationAndSetsUVOnlyAfterValidTokenProof() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      PINHost pin = new PINHost(fixture);
      pin.setPIN(PIN);
      Assertions.assertEquals(true, mapValue(fixture.success(0x04, null).get(4)).get("clientPin"));
      fixture.error(CTAP.PIN_REQUIRED, 0x01, make(RP, 1, true));
      byte[] token = pin.getToken(PIN);
      Registration registration = fixture.register(RP, 1, true, token);
      registration.verify();
      Assertions.assertEquals(0x45, registration.authData[32]);

      Map<Object, Object> request = assertion(RP, registration.id);
      assertSignature(fixture.success(0x02, request), registration, 1);
      request.put(5, map("uv", true));
      fixture.error(CTAP.UNSUPPORTED_OPTION, 0x02, request);
      request.put(6, auth(token, CLIENT_DATA_HASH));
      request.put(7, 1);
      Map<Object, Object> response = fixture.success(0x02, request);
      assertSignature(response, registration, 5);
      String label =
        " [" + Hex.toHexString(Arrays.copyOf(registration.id, 8)).toUpperCase(Locale.ROOT) + "]";
      Assertions.assertEquals("user-1" + label, mapValue(response.get(4)).get("name"));
      Assertions.assertEquals("User 1" + label, mapValue(response.get(4)).get("displayName"));

      byte[] invalid = auth(token, CLIENT_DATA_HASH);
      invalid[0] ^= 1;
      request.put(6, invalid);
      fixture.error(CTAP.PIN_AUTH_INVALID, 0x02, request);
      request.put(6, auth(token, CLIENT_DATA_HASH));
      request.put(5, map("uv", true, "up", false));
      assertSignature(fixture.success(0x02, request), registration, 4);
    }
  }

  @Test
  public void resetClearsOnlyCredentialTypeAndFIDOPIN() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      PINHost pin = new PINHost(fixture);
      pin.setPIN(PIN);
      Registration registration = fixture.register(RP, 1, true, pin.getToken(PIN));
      fixture.manage();
      byte[] seedPublicKey = fixture.seedPublicKey();
      byte[] other = new byte[10];
      other[0] = (byte) 0xF1;
      other[1] = 2;
      other[9] = 1;
      fixture.card.create(other, null, null, new byte[] { 7 }, false);
      fixture.select();
      fixture.success(0x07, null);
      Assertions.assertEquals(false, mapValue(fixture.success(0x04, null).get(4)).get("clientPin"));
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, registration.id));
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, null));
      fixture.manage();
      fixture.card.success(0x31, fields("index", fixture.seedIndex));
      Assertions.assertArrayEquals(seedPublicKey, fixture.seedPublicKey());
      Assertions.assertArrayEquals(
        new byte[] { 7 },
        fixture.card.success(0x32, fields("index", other)).bytes("data")
      );
      fixture.select();
      fixture.register(RP, 2, true, null).verify();
    }
  }

  @Test
  public void resetRequiresWritableTypeAndDenialDoesNotClearPINOrRecords() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      PINHost pin = new PINHost(fixture);
      pin.setPIN(PIN);
      byte[] token = pin.getToken(PIN);
      Registration registration = fixture.register(RP, 1, true, token);
      fixture.grant(false);
      // Authorization fails before credential/PIN writes; this needs no simulated rollback.
      fixture.error(CTAP.OPERATION_DENIED, 0x07, null);
      Assertions.assertEquals(true, mapValue(fixture.success(0x04, null).get(4)).get("clientPin"));
      assertSignature(fixture.success(0x02, assertion(RP, registration.id)), registration, 1);
      fixture.grant(true);
      fixture.success(0x07, null);
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, registration.id));
    }
  }

  @Test
  public void revocationAndReplacingSeedInvalidateUseOfExistingRecords() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Registration registration = fixture.register(RP, 1, true, null);
      Registration nonResident = fixture.register(RP, 2, false, null);
      fixture.manage();
      MonoidAppletGrantTest.success(
        fixture.card,
        0x52,
        fields("aid", AppletTest.aidBytes(FIDO_AID))
      );
      fixture.select();
      fixture.error(CTAP.OPERATION_DENIED, 0x02, assertion(RP, registration.id));
      fixture.grant(true);
      assertSignature(fixture.success(0x02, assertion(RP, registration.id)), registration, 1);
      fixture.manage();
      byte[] changed = sequence(64);
      changed[0] ^= 1;
      fixture.card.success(0x33, fields("index", fixture.seedIndex, "data", changed));
      fixture.select();
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, registration.id));
      fixture.error(CTAP.NO_CREDENTIALS, 0x02, assertion(RP, nonResident.id));
      fixture.manage();
      fixture.card.success(0x33, fields("index", fixture.seedIndex, "data", sequence(64)));
      fixture.select();
      assertSignature(fixture.success(0x02, assertion(RP, nonResident.id)), nonResident, 1);
    }
  }

  @Test
  public void shortAPDUChainingAndSmallGETRESPONSEPreserveTheCTAPMessage() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      fixture.frameLength = 17;
      fixture.responseLength = 23;
      Registration registration = fixture.register(RP, 1, true, null);
      registration.verify();
      Assertions.assertTrue(fixture.requestFrames > 1);
      Assertions.assertTrue(fixture.responseFrames > 1);
      assertSignature(fixture.success(0x02, assertion(RP, registration.id)), registration, 1);
      fixture.error(CTAP.INVALID_COMMAND, 0x7F, null);
      fixture.error(CTAP.INVALID_LENGTH, 0x04, map());
      Map<Object, Object> invalid = make(RP, 2, true);
      invalid.put(4, Arrays.asList(map("alg", -8, "type", "public-key")));
      fixture.error(CTAP.UNSUPPORTED_ALGORITHM, 0x01, invalid);
    }
  }

  static Map<Object, Object> make(String rp, int user, boolean resident) {
    return map(
      1,
      CLIENT_DATA_HASH,
      2,
      map("id", rp, "name", "Example"),
      3,
      map("id", new byte[] { (byte) user }, "name", "user-" + user, "displayName", "User " + user),
      4,
      Arrays.asList(map("alg", -7, "type", "public-key")),
      7,
      map("rk", resident)
    );
  }

  static Map<Object, Object> assertion(String rp, byte[] id) {
    Map<Object, Object> result = map(1, rp, 2, CLIENT_DATA_HASH);
    if (id != null) {
      result.put(3, Arrays.asList(descriptor(id)));
    }
    return result;
  }

  static Map<Object, Object> descriptor(byte[] id) {
    return map("id", id, "type", "public-key");
  }

  static byte[] index(byte[] id) {
    byte[] index = new byte[10];
    index[0] = (byte) 0xF1;
    index[1] = 1;
    System.arraycopy(id, 0, index, 2, 8);
    return index;
  }

  static void assertSignature(Map<Object, Object> response, Registration registration, int flags)
    throws Exception {
    Assertions.assertArrayEquals(registration.id, (byte[]) mapValue(response.get(1)).get("id"));
    byte[] authData = (byte[]) response.get(2);
    Assertions.assertEquals(37, authData.length);
    Assertions.assertEquals(flags, authData[32]);
    Assertions.assertArrayEquals(
      Arrays.copyOf(registration.authData, 32),
      Arrays.copyOf(authData, 32)
    );
    verify(registration.publicKey, authData, (byte[]) response.get(3));
  }

  private static void verify(PublicKey key, byte[] authData, byte[] signature) throws Exception {
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(key);
    verifier.update(authData);
    verifier.update(CLIENT_DATA_HASH);
    Assertions.assertTrue(verifier.verify(signature));
  }

  private static PublicKey publicKey(Map<Object, Object> cose) throws Exception {
    Assertions.assertEquals(2, cose.get(1));
    Assertions.assertEquals(1, cose.get(-1));
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec("secp256r1"));
    ECPoint point = new ECPoint(
      new BigInteger(1, (byte[]) cose.get(-2)),
      new BigInteger(1, (byte[]) cose.get(-3))
    );
    return KeyFactory.getInstance("EC").generatePublic(
      new ECPublicKeySpec(point, parameters.getParameterSpec(ECParameterSpec.class))
    );
  }

  private static byte[] auth(byte[] key, byte[] data) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    return Arrays.copyOf(mac.doFinal(data), 16);
  }

  private static Map<Object, Object> map(Object... entries) {
    Map<Object, Object> result = new LinkedHashMap<>();
    for (int index = 0; index < entries.length; index += 2) {
      result.put(entries[index], entries[index + 1]);
    }
    return result;
  }

  @SuppressWarnings("unchecked")
  static Map<Object, Object> mapValue(Object value) {
    return (Map<Object, Object>) value;
  }

  static final class Registration {

    final byte[] authData;
    final byte[] id;
    final PublicKey publicKey;
    final byte[] signature;

    Registration(Map<Object, Object> response, String rp) throws Exception {
      Assertions.assertEquals("packed", response.get(1));
      authData = (byte[]) response.get(2);
      Assertions.assertEquals(164, authData.length);
      Assertions.assertArrayEquals(
        MessageDigest.getInstance("SHA-256").digest(rp.getBytes(StandardCharsets.UTF_8)),
        Arrays.copyOf(authData, 32)
      );
      Assertions.assertEquals(0, authData[53]);
      Assertions.assertEquals(32, authData[54]);
      id = Arrays.copyOfRange(authData, 55, 87);
      Map<Object, Object> cose = mapValue(
        decode(Arrays.copyOfRange(authData, 87, authData.length))
      );
      Assertions.assertEquals(-7, cose.get(3));
      publicKey = publicKey(cose);
      Map<Object, Object> statement = mapValue(response.get(3));
      Assertions.assertEquals(-7, statement.get("alg"));
      signature = (byte[]) statement.get("sig");
    }

    void verify() throws Exception {
      MonoidSecurityKeyTest.verify(publicKey, authData, signature);
    }
  }

  static final class Fixture implements AutoCloseable {

    final Card card = new Card(true);
    final byte[] seedIndex;
    int frameLength = 255;
    int responseLength = 256;
    int requestFrames;
    int responseFrames;

    Fixture(boolean authorized) {
      byte[] aid = AppletTest.aidBytes(FIDO_AID);
      byte[] parameters = new byte[aid.length + 3];
      parameters[0] = (byte) aid.length;
      System.arraycopy(aid, 0, parameters, 1, aid.length);
      card.simulator.installApplet(
        FIDO_APPLET_AID,
        MonoidSecurityKeyApplet.class,
        parameters,
        (short) 0,
        (byte) parameters.length
      );
      card.reset();
      card.authenticate(false);
      seedIndex = card.create("seed", null, null, sequence(64), true);
      if (authorized) {
        grant(true);
      } else {
        select();
      }
    }

    void select() {
      ResponseAPDU response = card.simulator.transmitCommand(
        new CommandAPDU(0, 0xA4, 4, 0, AppletTest.aidBytes(FIDO_AID))
      );
      Assertions.assertEquals(0x9000, response.getSW());
      Assertions.assertArrayEquals(
        "FIDO_2_0".getBytes(StandardCharsets.US_ASCII),
        response.getData()
      );
    }

    void manage() {
      Assertions.assertTrue(card.simulator.selectApplet(MONOID_AID));
      card.authenticate(false);
    }

    void grant(boolean writable) {
      manage();
      MonoidAppletGrantTest.success(
        card,
        0x51,
        fields(
          "aid",
          AppletTest.aidBytes(FIDO_AID),
          "types",
          Arrays.asList(Arrays.asList((short) 0xF101, writable)),
          "seed",
          fields("index", seedIndex, "domain", "security-key".getBytes(StandardCharsets.US_ASCII))
        )
      );
      select();
    }

    byte[] seedPublicKey() {
      return MonoidAppletGrantTest.success(
        card,
        0x40,
        fields(
          "index",
          seedIndex,
          "type",
          "seed",
          "derivation",
          fields("type", "monoid-001", "context", new byte[] { 1, 2, 3 })
        )
      ).bytes("publicKey");
    }

    Registration register(String rp, int user, boolean resident, byte[] token) throws Exception {
      Map<Object, Object> request = make(rp, user, resident);
      if (token != null) {
        request.put(8, auth(token, CLIENT_DATA_HASH));
        request.put(9, 1);
      }
      return new Registration(success(0x01, request), rp);
    }

    Map<Object, Object> success(int command, Object request) {
      byte[] data = transmit(command, request);
      Assertions.assertEquals(0, data[0] & 0xFF, "CTAP command " + command);
      return data.length == 1 ? map() : mapValue(decode(Arrays.copyOfRange(data, 1, data.length)));
    }

    void error(int expected, int command, Object request) {
      byte[] data = transmit(command, request);
      Assertions.assertArrayEquals(new byte[] { (byte) expected }, data, "CTAP command " + command);
    }

    byte[] transmit(int command, Object request) {
      byte[] body = request == null ? new byte[0] : encode(request);
      byte[] data = new byte[body.length + 1];
      data[0] = (byte) command;
      System.arraycopy(body, 0, data, 1, body.length);
      ResponseAPDU response = null;
      requestFrames = 0;
      for (int offset = 0; offset < data.length; offset += frameLength) {
        int end = Math.min(data.length, offset + frameLength);
        boolean last = end == data.length;
        response = card.simulator.transmitCommand(
          new CommandAPDU(
            last ? 0x80 : 0x90,
            0x10,
            0,
            0,
            Arrays.copyOfRange(data, offset, end),
            responseLength
          )
        );
        requestFrames++;
        if (!last) {
          Assertions.assertEquals(0x9000, response.getSW());
          Assertions.assertEquals(0, response.getData().length);
        }
      }
      ByteArrayOutputStream result = new ByteArrayOutputStream();
      responseFrames = 0;
      for (;;) {
        result.write(response.getData(), 0, response.getData().length);
        responseFrames++;
        if (response.getSW1() != 0x61) {
          Assertions.assertEquals(0x9000, response.getSW());
          return result.toByteArray();
        }
        response = card.simulator.transmitCommand(new CommandAPDU(0, 0xC0, 0, 0, responseLength));
      }
    }

    @Override
    public void close() {
      card.simulator.deleteApplet(FIDO_AID);
      card.close();
    }
  }

  private static final class PINHost {

    final Fixture fixture;
    final Map<Object, Object> cose;
    final byte[] secret;

    PINHost(Fixture fixture) throws Exception {
      this.fixture = fixture;
      Map<Object, Object> remote = mapValue(fixture.success(0x06, map(1, 1, 2, 2)).get(1));
      Assertions.assertEquals(-25, remote.get(3));
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp256r1"));
      KeyPair pair = generator.generateKeyPair();
      ECPublicKey key = (ECPublicKey) pair.getPublic();
      cose = map(
        1,
        2,
        3,
        -25,
        -1,
        1,
        -2,
        coordinate(key.getW().getAffineX()),
        -3,
        coordinate(key.getW().getAffineY())
      );
      KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
      agreement.init(pair.getPrivate());
      agreement.doPhase(publicKey(remote), true);
      secret = MessageDigest.getInstance("SHA-256").digest(agreement.generateSecret());
    }

    void setPIN(byte[] pin) throws Exception {
      byte[] encrypted = crypt(Cipher.ENCRYPT_MODE, Arrays.copyOf(pin, 64));
      fixture.success(0x06, map(1, 1, 2, 3, 3, cose, 4, auth(secret, encrypted), 5, encrypted));
    }

    byte[] getToken(byte[] pin) throws Exception {
      byte[] hash = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(pin), 16);
      Map<Object, Object> result = fixture.success(
        0x06,
        map(1, 1, 2, 5, 3, cose, 6, crypt(Cipher.ENCRYPT_MODE, hash))
      );
      return crypt(Cipher.DECRYPT_MODE, (byte[]) result.get(2));
    }

    byte[] crypt(int mode, byte[] value) throws Exception {
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(mode, new SecretKeySpec(secret, "AES"), new IvParameterSpec(new byte[16]));
      return cipher.doFinal(value);
    }

    static byte[] coordinate(BigInteger number) {
      byte[] bytes = number.toByteArray();
      byte[] result = new byte[32];
      int length = Math.min(bytes.length, 32);
      System.arraycopy(bytes, bytes.length - length, result, 32 - length, length);
      return result;
    }
  }

  private static byte[] encode(Object value) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    write(output, value);
    return output.toByteArray();
  }

  private static void write(ByteArrayOutputStream output, Object value) {
    if (value instanceof Map) {
      Map<?, ?> map = (Map<?, ?>) value;
      header(output, 5, map.size());
      List<Object> keys = new ArrayList<>(map.keySet());
      keys.sort((a, b) -> compare(encode(a), encode(b)));
      for (Object key : keys) {
        write(output, key);
        write(output, map.get(key));
      }
    } else if (value instanceof List) {
      List<?> list = (List<?>) value;
      header(output, 4, list.size());
      for (Object entry : list) {
        write(output, entry);
      }
    } else if (value instanceof byte[]) {
      byte[] bytes = (byte[]) value;
      header(output, 2, bytes.length);
      output.write(bytes, 0, bytes.length);
    } else if (value instanceof String) {
      byte[] bytes = ((String) value).getBytes(StandardCharsets.UTF_8);
      header(output, 3, bytes.length);
      output.write(bytes, 0, bytes.length);
    } else if (value instanceof Boolean) {
      output.write((Boolean) value ? 0xF5 : 0xF4);
    } else {
      int integer = ((Number) value).intValue();
      header(output, integer < 0 ? 1 : 0, integer < 0 ? -1 - integer : integer);
    }
  }

  private static int compare(byte[] left, byte[] right) {
    for (int offset = 0; offset < Math.min(left.length, right.length); offset++) {
      int difference = (left[offset] & 0xFF) - (right[offset] & 0xFF);
      if (difference != 0) {
        return difference;
      }
    }
    return Integer.compare(left.length, right.length);
  }

  private static void header(ByteArrayOutputStream output, int type, int length) {
    if (length < 24) {
      output.write((type << 5) | length);
    } else if (length <= 255) {
      output.write((type << 5) | 24);
      output.write(length);
    } else {
      output.write((type << 5) | 25);
      output.write(length >> 8);
      output.write(length);
    }
  }

  private static Object decode(byte[] data) {
    int[] offset = { 0 };
    Object value = read(data, offset);
    Assertions.assertEquals(data.length, offset[0]);
    return value;
  }

  private static Object read(byte[] data, int[] offset) {
    int initial = data[offset[0]++] & 0xFF;
    int type = initial >> 5;
    int value = initial & 31;
    if (type == 7) {
      Assertions.assertTrue(value == 20 || value == 21);
      return value == 21;
    }
    if (value == 24) {
      value = data[offset[0]++] & 0xFF;
    } else if (value == 25) {
      value = ((data[offset[0]++] & 0xFF) << 8) | (data[offset[0]++] & 0xFF);
    }
    if (type == 0 || type == 1) {
      return type == 0 ? value : -1 - value;
    }
    if (type == 2 || type == 3) {
      byte[] bytes = Arrays.copyOfRange(data, offset[0], offset[0] + value);
      offset[0] += value;
      return type == 2 ? bytes : new String(bytes, StandardCharsets.UTF_8);
    }
    if (type == 4) {
      List<Object> result = new ArrayList<>();
      for (int index = 0; index < value; index++) {
        result.add(read(data, offset));
      }
      return result;
    }
    Assertions.assertEquals(5, type);
    Map<Object, Object> result = map();
    for (int index = 0; index < value; index++) {
      Object key = read(data, offset);
      Assertions.assertFalse(result.containsKey(key));
      result.put(key, read(data, offset));
    }
    return result;
  }
}
