package tests;

import static tests.AppletTest.aidBytes;
import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.fields;

import com.licel.jcardsim.utils.AIDUtil;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javacard.framework.AID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import monoididentity.LibSECP256r1;
import monoidlib.CBOR;
import monoidlib.CBORBufferReader;
import monoidotp.MonoidOTPApplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

/** APDU and real SIO-context integration; jCardSim does not establish card firewall behavior. */
public class MonoidOTPTest {

  private static final AID MONOID_AID = AIDUtil.create("f06d6f6e6f69640201");
  private static final AID OTP_AID = AIDUtil.create("f06d6f6e6f69640501");
  private static final short ACCOUNT_TYPE = (short) 0xF201;
  private static final byte[] DOMAIN = ascii("Monoid Authority Time");
  private static final String[] ALGORITHMS = { "HmacSHA1", "HmacSHA256", "HmacSHA512" };
  private static final byte[][] SECRETS = {
    ascii("12345678901234567890"),
    ascii("12345678901234567890123456789012"),
    ascii("1234567890123456789012345678901234567890123456789012345678901234"),
  };

  @Test
  public void rfc6238AllAlgorithmsAndSixTimesMatchIndependentThreeWindowHmac() throws Exception {
    // RFC 6238 Appendix B: https://www.rfc-editor.org/rfc/rfc6238.html#appendix-B
    long[] times = { 59, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L };
    String[][] expected = {
      { "94287082", "46119246", "90693936" },
      { "07081804", "68084774", "25091201" },
      { "14050471", "67062674", "99943326" },
      { "89005924", "91819424", "93441116" },
      { "69279037", "90698825", "38618901" },
      { "65353130", "77737706", "47863826" },
    };

    try (Fixture fixture = new Fixture(true)) {
      Account[] accounts = new Account[3];

      for (int algorithm = 0; algorithm < accounts.length; algorithm++) {
        accounts[algorithm] = fixture.account(algorithm + 1, 8, 30, SECRETS[algorithm], true);
      }

      Map<String, Object> hello = response(fixture.otp(0x20, fields()));

      Assertions.assertEquals(2, hello.size());
      Assertions.assertEquals(3, ((Number) hello.get("batchSize")).intValue());
      Assertions.assertEquals(2, ((byte[]) hello.get("version")).length);

      for (int vector = 0; vector < times.length; vector++) {
        fixture.prepare(times[vector], accounts);
        fixture.authorize();

        Result calculated = fixture.otp(0x23, fields());
        List<Map<String, Object>> items = assertBatch(calculated, times[vector], accounts);

        for (int algorithm = 0; algorithm < accounts.length; algorithm++) {
          Assertions.assertEquals(expected[vector][algorithm], codes(items.get(algorithm)).get(0));
        }

        Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);
      }
    }
  }

  @Test
  public void accountsKeepOrderAcrossFragmentedRequestsAndResponses() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Account[] accounts = new Account[16];
      int[] periods = { 1, 30, 60, 32767 };

      for (int index = 0; index < accounts.length; index++) {
        int algorithm = index % 3;
        byte[] secret = SECRETS[algorithm].clone();
        secret[secret.length - 1] ^= (byte) index;

        accounts[accounts.length - index - 1] = fixture.account(
          algorithm + 1,
          index % 2 == 0 ? 6 : 8,
          periods[index % periods.length],
          secret,
          index % 2 != 0
        );
      }

      long time = Long.MIN_VALUE + 123456789;
      byte[] challenge = fixture.challenge();
      Map<String, Object> proof = proof(time, challenge, accounts);
      Result prepared = fixture.otp(
        0x22,
        fields(
          "indices",
          proof.get("indices"),
          "signature",
          proof.get("signature"),
          "data",
          proof.get("data")
        ),
        7
      );
      prepared.assertSuccess();

      Assertions.assertTrue(prepared.requestFrames > 1);

      fixture.authorize();

      Result calculated = fixture.otp(0x23, fields());
      assertBatch(calculated, time, accounts);

      Assertions.assertTrue(calculated.responseFrames > 1);
    }
  }

  @Test
  public void accountSecretsAreUnreadableAndDuplicateSecretsCannotCreateAnotherAccount()
    throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Account first = fixture.account(1, 6, 30, SECRETS[0], true);

      fixture.select(MONOID_AID);
      fixture.card.authenticate(false);

      assertError(fixture.card.transmit(0x32, fields("index", first.index)), "ACCESS_DENIED");
      assertError(
        fixture.card.transmit(
          0x34,
          fields(
            "type",
            ACCOUNT_TYPE,
            "metadata",
            new byte[] { 1, 1, 8, 0, 60 },
            "alias",
            "another label",
            "data",
            SECRETS[0]
          )
        ),
        "EXISTS"
      );

      fixture.prepare(59, first);
      fixture.authorize();
      assertBatch(fixture.otp(0x23, fields()), 59, first);
    }
  }

  @Test
  public void authenticationIsRequiredOnceAndFailedCalculateConsumesItsBatch() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Account account = fixture.account(1, 6, 30, SECRETS[0], true);
      fixture.prepare(59, account);

      Assertions.assertEquals(0x6982, fixture.otp(0x23, fields()).status);

      fixture.authorize();

      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);

      fixture.prepare(59, account);
      fixture.authorize();
      assertBatch(fixture.otp(0x23, fields()), 59, account);

      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);
    }
  }

  @Test
  public void challengeAndPrepareEachRevokePreviouslyGrantedUserAuthentication() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Account account = fixture.account(1, 6, 30, SECRETS[0], true);
      byte[] first = fixture.challenge();
      fixture.authorize();
      fixture.otp(0x22, proof(59, first, account)).assertSuccess();

      Assertions.assertEquals(0x6982, fixture.otp(0x23, fields()).status);

      fixture.prepare(59, account);
      fixture.authorize();

      byte[] replacement = fixture.challenge();

      Assertions.assertFalse(Arrays.equals(first, replacement));

      fixture.otp(0x22, proof(89, replacement, account)).assertSuccess();

      Assertions.assertEquals(0x6982, fixture.otp(0x23, fields()).status);

      fixture.prepare(89, account);
      fixture.authorize();
      assertBatch(fixture.otp(0x23, fields()), 89, account);
    }
  }

  @Test
  public void wrongProofOrNonceConsumesChallengeAndCannotBeRetried() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Account account = fixture.account(1, 8, 30, SECRETS[0], true);

      for (int mutation = 0; mutation < 4; mutation++) {
        byte[] challenge = fixture.challenge();
        Map<String, Object> valid = proof(59, challenge, account);
        Map<String, Object> changed = proof(59, challenge, account);

        if (mutation == 0) {
          ((byte[]) changed.get("signature"))[0] ^= 1;
        } else if (mutation == 1) {
          ((byte[]) changed.get("data"))[8] ^= 1;
        } else if (mutation == 2) {
          byte[] wrong = challenge.clone();
          wrong[0] ^= 1;
          changed = proof(59, wrong, account);
        } else {
          byte[] data = (byte[]) changed.get("data");
          data[0] = 2;
          changed.put("signature", sign(data));
        }

        Assertions.assertEquals(mutation == 3 ? 0x6A80 : 0x6982, fixture.otp(0x22, changed).status);
        Assertions.assertEquals(0x6985, fixture.otp(0x22, valid).status);

        fixture.authorize();

        Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);
      }

      byte[] abandoned = fixture.challenge();
      fixture.challenge();

      Assertions.assertEquals(0x6982, fixture.otp(0x22, proof(59, abandoned, account)).status);

      fixture.prepare(59, account);
      fixture.authorize();
      assertBatch(fixture.otp(0x23, fields()), 59, account);
    }
  }

  @Test
  public void identityWithoutAuthorityRejectsAnOtherwiseValidSignedTime() throws Exception {
    try (Fixture fixture = new Fixture(false)) {
      Account account = fixture.account(1, 6, 30, SECRETS[0], false);
      byte[] challenge = fixture.challenge();

      Assertions.assertEquals(0x6982, fixture.otp(0x22, proof(59, challenge, account)).status);
      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);
    }
  }

  @Test
  public void appTimeWithoutAuthorityNeedsNoChallengeAndMatchesAllAlgorithms() throws Exception {
    long[] times = {
      59,
      1111111109L,
      1111111111L,
      1234567890L,
      2000000000L,
      20000000000L,
      Long.MIN_VALUE + 123456789,
      -1,
      0,
    };

    try (Fixture fixture = new Fixture(false)) {
      Account[] accounts = new Account[3];

      for (int algorithm = 0; algorithm < accounts.length; algorithm++) {
        accounts[algorithm] = fixture.account(algorithm + 1, 8, 30, SECRETS[algorithm], true);
      }

      for (long time : times) {
        Map<String, Object> request = appTime(time, accounts);
        Result prepared = fixture.otp(
          0x22,
          fields("indices", request.get("indices"), "time", request.get("time")),
          7
        );
        prepared.assertSuccess();

        Assertions.assertTrue(prepared.requestFrames > 1);

        fixture.authorize();
        assertBatch(fixture.otp(0x23, fields()), time, accounts);

        Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);
      }
    }
  }

  @Test
  public void configuredAuthorityRejectsAppTimeWithoutFallbackAndConsumesPendingChallenge()
    throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Account account = fixture.account(1, 6, 30, SECRETS[0], true);

      Assertions.assertEquals(0x6982, fixture.otp(0x22, appTime(59, account)).status);
      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);

      byte[] challenge = fixture.challenge();
      fixture.authorize();

      Assertions.assertEquals(0x6982, fixture.otp(0x22, appTime(59, account)).status);
      Assertions.assertEquals(0x6985, fixture.otp(0x22, proof(59, challenge, account)).status);
      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);

      Map<String, Object> invalid = proof(59, fixture.challenge(), account);
      ((byte[]) invalid.get("signature"))[0] ^= 1;

      Assertions.assertEquals(0x6982, fixture.otp(0x22, invalid).status);
      Assertions.assertEquals(0x6982, fixture.otp(0x22, appTime(59, account)).status);

      fixture.prepare(59, account);

      Assertions.assertEquals(0x6982, fixture.otp(0x23, fields()).status);

      fixture.prepare(59, account);
      fixture.authorize();
      assertBatch(fixture.otp(0x23, fields()), 59, account);
    }
  }

  @Test
  public void appTimeCannotBeMixedWithEitherSignedProofField() throws Exception {
    for (boolean authority : new boolean[] { false, true }) {
      try (Fixture fixture = new Fixture(authority)) {
        Account account = fixture.account(1, 6, 30, SECRETS[0], true);

        for (String field : new String[] { "data", "signature" }) {
          Map<String, Object> request = appTime(59, account);
          request.put(field, new byte[field.equals("data") ? 41 : 64]);

          Assertions.assertEquals(0x6A80, fixture.otp(0x22, request).status);
          Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);
        }
      }
    }
  }

  @Test
  public void appTimePreparationRequiresNewPermissionAndResetDropsTheBatch() throws Exception {
    try (Fixture fixture = new Fixture(false)) {
      Account account = fixture.account(2, 8, 60, SECRETS[1], true);

      fixture.otp(0x22, appTime(59, account)).assertSuccess();

      Assertions.assertEquals(0x6982, fixture.otp(0x23, fields()).status);

      fixture.authorize();

      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);

      fixture.otp(0x22, appTime(59, account)).assertSuccess();
      fixture.authorize();
      fixture.otp(0x22, appTime(89, account)).assertSuccess();

      Assertions.assertEquals(0x6982, fixture.otp(0x23, fields()).status);

      fixture.otp(0x22, appTime(89, account)).assertSuccess();
      fixture.authorize();
      fixture.select(MONOID_AID);
      fixture.select(OTP_AID);
      assertBatch(fixture.otp(0x23, fields()), 89, account);

      fixture.otp(0x22, appTime(89, account)).assertSuccess();
      fixture.authorize();
      fixture.card.reset();

      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);

      fixture.otp(0x22, appTime(89, account)).assertSuccess();

      Assertions.assertEquals(0x6982, fixture.otp(0x23, fields()).status);

      fixture.otp(0x22, appTime(89, account)).assertSuccess();
      fixture.authorize();
      fixture.challenge();

      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);

      fixture.otp(0x22, appTime(89, account)).assertSuccess();

      Assertions.assertEquals(0x6982, fixture.otp(0x23, fields()).status);
    }
  }

  @Test
  public void malformedAppTimeCannotRetainAnOldBatchOrReuseItsAuthorization() throws Exception {
    try (Fixture fixture = new Fixture(false)) {
      Account account = fixture.account(1, 6, 30, SECRETS[0], true);

      for (Object invalid : new Object[] { new byte[0], new byte[7], new byte[9], 59 }) {
        fixture.otp(0x22, appTime(59, account)).assertSuccess();
        fixture.authorize();

        Map<String, Object> request = appTime(59, account);
        request.put("time", invalid);

        Assertions.assertNotEquals(0x9000, fixture.otp(0x22, request).status);
        Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);

        fixture.otp(0x22, appTime(59, account)).assertSuccess();

        Assertions.assertEquals(0x6982, fixture.otp(0x23, fields()).status);
      }
    }
  }

  @Test
  public void prepareRejectsEmptyDuplicateWrongTypeWrongLengthAndOversizedAccountSets()
    throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Account account = fixture.account(1, 6, 30, SECRETS[0], true);
      byte[] otherType = account.index.clone();
      otherType[1] ^= 1;
      byte[][] oversized = new byte[17][];

      for (int index = 0; index < oversized.length; index++) {
        oversized[index] = accountIndex(index + 100);
      }

      for (byte[][] indices : new byte[][][] {
        new byte[0][],
        { account.index, account.index },
        { otherType },
        { Arrays.copyOf(account.index, 9) },
        { Arrays.copyOf(account.index, 11) },
        oversized,
      }) {
        Map<String, Object> request = proof(59, fixture.challenge(), account);
        request.put("indices", indices);

        Assertions.assertNotEquals(0x9000, fixture.otp(0x22, request).status);
        Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);
      }

      fixture.prepare(59, account);

      Assertions.assertEquals(0x6985, fixture.otp(0x22, fields()).status);

      fixture.authorize();

      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);
    }
  }

  @Test
  public void invalidAccountConfigurationConsumesThePermitAndDoesNotYieldCodes() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      byte[][] configurations = {
        null,
        new byte[4],
        new byte[6],
        { 0, 1, 6, 0, 30 },
        { 1, 0, 6, 0, 30 },
        { 1, 4, 6, 0, 30 },
        { 1, 1, 7, 0, 30 },
        { 1, 1, 6, 0, 0 },
        { 1, 1, 6, (byte) 0x80, 0 },
      };

      for (byte[] configuration : configurations) {
        Account account = fixture.account(configuration, SECRETS[0], false);
        fixture.prepare(59, account);
        fixture.authorize();

        Result result = fixture.otp(0x23, fields());

        Assertions.assertEquals(0x6A80, result.status);
        Assertions.assertEquals(0, result.data.length);
        Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);

        fixture.select(MONOID_AID);
        fixture.card.authenticate(false);
        fixture.card.success(0x35, fields("index", account.index));
      }

      Account missing = new Account(accountIndex(32000), 1, 6, 30, SECRETS[0]);
      fixture.prepare(59, missing);
      fixture.authorize();

      Assertions.assertEquals(0x6A83, fixture.otp(0x23, fields()).status);
      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);
    }
  }

  @Test
  public void failureAfterAValidAccountClearsAllPendingResponseBytes() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Account valid = fixture.account(1, 8, 30, SECRETS[0], true);
      Account invalid = fixture.account(new byte[] { 1, 1, 7, 0, 30 }, SECRETS[1], false);
      fixture.prepare(59, valid, invalid);
      fixture.authorize();

      Result result = fixture.otp(0x23, fields());

      Assertions.assertEquals(0x6A80, result.status);
      Assertions.assertEquals(0, result.data.length);

      // Do not SELECT again: deselection would conceal a stale writer buffer.
      Assertions.assertEquals(
        0x6985,
        fixture.card.simulator.transmitCommand(new CommandAPDU(0, 0xC0, 0, 0, 256)).getSW()
      );
      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);

      fixture.prepare(59, valid);
      fixture.authorize();
      assertBatch(fixture.otp(0x23, fields()), 59, valid);
    }
  }

  @Test
  public void cardResetDropsPreparedBatchAndAuthorizationWhileOrdinarySelectPreservesThem()
    throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Account account = fixture.account(2, 8, 60, SECRETS[1], true);
      fixture.prepare(1234567890, account);
      fixture.authorize();
      fixture.card.reset();

      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);

      fixture.prepare(1234567890, account);

      Assertions.assertEquals(0x6982, fixture.otp(0x23, fields()).status);

      fixture.prepare(1234567890, account);
      fixture.authorize();
      fixture.select(MONOID_AID);
      fixture.select(OTP_AID);

      assertBatch(fixture.otp(0x23, fields()), 1234567890, account);
    }
  }

  @Test
  public void malformedCalculateCannotRestoreOrReuseThePreparedBatch() throws Exception {
    try (Fixture fixture = new Fixture(true)) {
      Account account = fixture.account(1, 6, 30, SECRETS[0], true);
      fixture.prepare(59, account);
      fixture.authorize();
      fixture.select(OTP_AID);

      Assertions.assertNotEquals(
        0x9000,
        fixture.card.simulator
          .transmitCommand(new CommandAPDU(0, 0x23, 0, 0, new byte[] { 0 }))
          .getSW()
      );
      Assertions.assertEquals(0x6985, fixture.otp(0x23, fields()).status);

      fixture.prepare(59, account);

      Assertions.assertEquals(0x6982, fixture.otp(0x23, fields()).status);
    }
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> assertBatch(
    Result result,
    long seconds,
    Account... accounts
  ) throws Exception {
    Map<String, Object> response = response(result);

    Assertions.assertEquals(2, response.size());
    Assertions.assertArrayEquals(
      ByteBuffer.allocate(8).putLong(seconds).array(),
      (byte[]) response.get("time")
    );

    List<Map<String, Object>> items = (List<Map<String, Object>>) response.get("items");

    Assertions.assertEquals(accounts.length, items.size());

    for (int index = 0; index < accounts.length; index++) {
      Account account = accounts[index];
      Map<String, Object> item = items.get(index);

      Assertions.assertEquals(3, item.size());
      Assertions.assertArrayEquals(account.index, (byte[]) item.get("index"));
      Assertions.assertEquals(account.period, ((Number) item.get("period")).intValue());
      Assertions.assertEquals(3, codes(item).size());

      for (int window = 0; window < 3; window++) {
        Assertions.assertEquals(hostCode(account, seconds, window), codes(item).get(window));
      }
    }

    return items;
  }

  @SuppressWarnings("unchecked")
  private static List<String> codes(Map<String, Object> item) {
    return (List<String>) item.get("codes");
  }

  private static String hostCode(Account account, long seconds, int window) throws Exception {
    BigInteger time = new BigInteger(1, ByteBuffer.allocate(8).putLong(seconds).array());
    BigInteger counter = time
      .divide(BigInteger.valueOf(account.period))
      .add(BigInteger.valueOf(window));
    byte[] encoded = ByteBuffer.allocate(8).putLong(counter.longValue()).array();
    String algorithm = ALGORITHMS[account.algorithm - 1];
    Mac mac = Mac.getInstance(algorithm);
    mac.init(new SecretKeySpec(account.secret, algorithm));
    byte[] hash = mac.doFinal(encoded);
    int offset = hash[hash.length - 1] & 15;
    int binary = ByteBuffer.wrap(hash).getInt(offset) & 0x7FFFFFFF;
    int modulus = account.digits == 6 ? 1000000 : 100000000;

    return String.format(Locale.ROOT, "%0" + account.digits + "d", binary % modulus);
  }

  private static Map<String, Object> proof(long seconds, byte[] challenge, Account... accounts)
    throws Exception {
    byte[] data = ByteBuffer.allocate(41).put((byte) 1).putLong(seconds).put(challenge).array();
    byte[][] indices = new byte[accounts.length][];

    for (int index = 0; index < accounts.length; index++) {
      indices[index] = accounts[index].index;
    }

    return fields("data", data, "signature", sign(data), "indices", indices);
  }

  private static Map<String, Object> appTime(long seconds, Account... accounts) {
    byte[][] indices = new byte[accounts.length][];

    for (int index = 0; index < accounts.length; index++) {
      indices[index] = accounts[index].index;
    }

    return fields("time", ByteBuffer.allocate(8).putLong(seconds).array(), "indices", indices);
  }

  private static byte[] sign(byte[] data) throws Exception {
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec("secp256r1"));
    Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
    signature.initSign(
      KeyFactory.getInstance("EC").generatePrivate(
        new ECPrivateKeySpec(BigInteger.ONE, parameters.getParameterSpec(ECParameterSpec.class))
      )
    );
    signature.update(DOMAIN);
    signature.update(data);

    return signature.sign();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> response(Result result) {
    result.assertSuccess();

    return (Map<String, Object>) read(new CBORBufferReader(result.data));
  }

  private static Object read(CBORBufferReader reader) {
    if (reader.is(CBOR.TYPE_MAP)) {
      short length = reader.map();
      Map<String, Object> result = new LinkedHashMap<>();

      for (short index = 0; index < length; index++) {
        result.put(new String(reader.text(), StandardCharsets.US_ASCII), read(reader));
      }

      return result;
    }

    if (reader.is(CBOR.TYPE_ARRAY)) {
      short length = reader.array();
      List<Object> result = new ArrayList<>();

      for (short index = 0; index < length; index++) {
        result.add(read(reader));
      }

      return result;
    }

    if (reader.is(CBOR.TYPE_BYTES)) {
      return reader.bytes().clone();
    }

    if (reader.is(CBOR.TYPE_TEXT)) {
      return new String(reader.text(), StandardCharsets.US_ASCII);
    }

    return reader.integer();
  }

  private static byte[] accountIndex(int value) {
    byte[] index = new byte[10];
    index[0] = (byte) 0xF2;
    index[1] = 1;
    index[8] = (byte) (value >> 8);
    index[9] = (byte) value;

    return index;
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private static final class Account {

    private final byte[] index;
    private final int algorithm;
    private final int digits;
    private final int period;
    private final byte[] secret;

    private Account(byte[] index, int algorithm, int digits, int period, byte[] secret) {
      this.index = index;
      this.algorithm = algorithm;
      this.digits = digits;
      this.period = period;
      this.secret = secret;
    }
  }

  private static final class Fixture implements AutoCloseable {

    private final Card card;

    private Fixture(boolean authority) {
      byte[] url = ascii("https://authority.example/");
      byte[] installation = new byte[66 + url.length];
      installation[0] = 2;
      System.arraycopy(LibSECP256r1.G, 0, installation, 1, 65);
      System.arraycopy(url, 0, installation, 66, url.length);

      card = new Card(true, authority ? installation : new byte[0]);
      card.simulator.installApplet(OTP_AID, MonoidOTPApplet.class);
      select(MONOID_AID);
      card.authenticate(false);
      grant();
    }

    private void grant() {
      MonoidAppletGrantTest.success(
        card,
        0x51,
        fields("aid", aidBytes(OTP_AID), "types", Arrays.asList(Arrays.asList(ACCOUNT_TYPE, false)))
      );
    }

    private Account account(
      int algorithm,
      int digits,
      int period,
      byte[] secret,
      boolean protectedData
    ) {
      byte[] configuration = {
        1,
        (byte) algorithm,
        (byte) digits,
        (byte) (period >> 8),
        (byte) period,
      };
      Account created = account(configuration, secret, protectedData);

      return new Account(created.index, algorithm, digits, period, secret);
    }

    private Account account(byte[] configuration, byte[] secret, boolean protectedData) {
      select(MONOID_AID);
      card.authenticate(false);

      byte[] index = card.create(ACCOUNT_TYPE, configuration, "OTP account", secret, protectedData);

      return new Account(index, 0, 0, 0, secret);
    }

    private void select(AID aid) {
      Assertions.assertTrue(card.simulator.selectApplet(aid));
    }

    private Result otp(int instruction, Map<String, Object> request) {
      return otp(instruction, request, 255);
    }

    private Result otp(int instruction, Map<String, Object> request, int frameLength) {
      select(OTP_AID);

      return card.transmit(instruction, request, frameLength);
    }

    private byte[] challenge() {
      Result result = otp(0x21, fields());
      result.assertSuccess();
      byte[] challenge = result.bytes("challenge");

      Assertions.assertEquals(32, challenge.length);

      return challenge;
    }

    private void prepare(long seconds, Account... accounts) throws Exception {
      otp(0x22, proof(seconds, challenge(), accounts)).assertSuccess();
    }

    private void authorize() {
      select(MONOID_AID);
      card.success(0x21, fields("pin", "123456", "aid", aidBytes(OTP_AID)));
      select(OTP_AID);
    }

    @Override
    public void close() {
      card.simulator.deleteApplet(OTP_AID);
      card.close();
    }
  }
}
