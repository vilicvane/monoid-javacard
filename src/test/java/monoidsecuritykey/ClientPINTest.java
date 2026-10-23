package monoidsecuritykey;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoidlib.CBORMap;
import monoidlib.CBORReader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

public class ClientPINTest {

  private static final byte[] PIN = "314159".getBytes(StandardCharsets.UTF_8);
  private static final byte[] NEXT_PIN = "271828".getBytes(StandardCharsets.UTF_8);
  private static final byte[] WRONG_PIN = "000000".getBytes(StandardCharsets.UTF_8);
  private static final byte[] CLIENT_DATA_HASH = new byte[32];
  private static final String PIN_APPLET_AID = "f06d6f6e6f69647c01";
  private static final String OTHER_APPLET_AID = "f06d6f6e6f69647d01";
  private static final String COMMAND_APPLET_AID = "f06d6f6e6f69647c02";

  private CardSimulator simulator;
  private ClientPIN clientPIN;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    simulator = new CardSimulator();
    simulator.installApplet(AIDUtil.create(PIN_APPLET_AID), PINApplet.class);
    simulator.installApplet(AIDUtil.create(OTHER_APPLET_AID), OtherApplet.class);
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(PIN_APPLET_AID)));
    clientPIN = PINApplet.installed.clientPIN;
  }

  @AfterEach
  public void disposeCommands() {
    Command.dispose();
  }

  @Test
  public void sharedScratchAllowsTokenOutputToReplaceTheConsumedPeerKey() throws Exception {
    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    byte[] expected = host.getToken(PIN);

    for (int length : new int[] { 133, 260 }) {
      byte[] scratch = new byte[length];
      Arrays.fill(scratch, (byte) 0x5A);
      int pointOffset = length - 65;
      int hashOffset = pointOffset - 16;
      int tokenOffset = length - 32;
      System.arraycopy(host.publicKey, 0, scratch, pointOffset, 65);
      System.arraycopy(host.encrypt(pinHash(PIN)), 0, scratch, hashOffset, 16);
      byte[] original = scratch.clone();

      Assertions.assertEquals(
        32,
        clientPIN.getPINToken(
          scratch,
          (short) pointOffset,
          scratch,
          (short) hashOffset,
          scratch,
          (short) tokenOffset
        )
      );

      Assertions.assertArrayEquals(
        Arrays.copyOf(original, tokenOffset),
        Arrays.copyOf(scratch, tokenOffset)
      );
      byte[] token = host.crypt(
        Cipher.DECRYPT_MODE,
        Arrays.copyOfRange(scratch, tokenOffset, length)
      );
      Assertions.assertArrayEquals(expected, token);
      clientPIN.verify(auth(token, CLIENT_DATA_HASH), CLIENT_DATA_HASH);
      Assertions.assertFalse(((OwnerPIN) field("pin").get(clientPIN)).isValidated());
    }
  }

  @Test
  public void offsetPINFailureStillRotatesECDHAndConsumesOnlyOneRetry() throws Exception {
    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    byte[] scratch = new byte[260];
    System.arraycopy(host.publicKey, 0, scratch, 195, 65);
    System.arraycopy(host.encrypt(pinHash(WRONG_PIN)), 0, scratch, 179, 16);

    assertError(CTAP.PIN_INVALID, () ->
      clientPIN.getPINToken(scratch, (short) 195, scratch, (short) 179, scratch, (short) 228)
    );

    Assertions.assertEquals(7, clientPIN.getRetries());
    Assertions.assertFalse(Arrays.equals(host.authenticatorPublicKey, publicKey()));
    Assertions.assertFalse(((OwnerPIN) field("pin").get(clientPIN)).isValidated());
    Host refreshed = new Host(clientPIN);
    System.arraycopy(refreshed.publicKey, 0, scratch, 195, 65);
    System.arraycopy(refreshed.encrypt(pinHash(PIN)), 0, scratch, 179, 16);
    Assertions.assertEquals(
      32,
      clientPIN.getPINToken(scratch, (short) 195, scratch, (short) 179, scratch, (short) 228)
    );
    byte[] token = refreshed.crypt(Cipher.DECRYPT_MODE, Arrays.copyOfRange(scratch, 228, 260));
    clientPIN.verify(auth(token, CLIENT_DATA_HASH), CLIENT_DATA_HASH);
    Assertions.assertEquals(8, clientPIN.getRetries());
  }

  @Test
  public void commandScratchSurvivesResponseWindowsAndRepeatedPINCommands() throws Exception {
    initializeCommands();
    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    byte[] expectedToken = host.getToken(PIN);
    byte[] request = tokenRequest(cose(host.publicKey), host.encrypt(pinHash(PIN)));

    for (int repeat = 0; repeat < 2; repeat++) {
      Assertions.assertArrayEquals(
        concatenate(new byte[] { 0, (byte) 0xA1, 1 }, cose(host.authenticatorPublicKey)),
        command(new byte[] { 6, (byte) 0xA2, 1, 1, 2, 2 })
      );
      byte[] response = command(request);
      Assertions.assertArrayEquals(
        new byte[] { 0, (byte) 0xA1, 2, 0x58, 0x20 },
        Arrays.copyOf(response, 5)
      );
      byte[] token = host.crypt(
        Cipher.DECRYPT_MODE,
        Arrays.copyOfRange(response, 5, response.length)
      );
      Assertions.assertArrayEquals(expectedToken, token);
      clientPIN.verify(auth(token, CLIENT_DATA_HASH), CLIENT_DATA_HASH);

      if (repeat == 0) {
        Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(OTHER_APPLET_AID)));
        Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(COMMAND_APPLET_AID)));
      }
    }
  }

  @Test
  public void reusedCommandMapsRejectMissingAndMalformedFieldsBeforePINChecks() throws Exception {
    initializeCommands();
    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    byte[] point = cose(host.publicKey);
    byte[] hash = host.encrypt(pinHash(PIN));
    byte[] valid = tokenRequest(point, hash);
    Assertions.assertEquals(0, command(valid)[0]);

    byte[] missingHash = Arrays.copyOf(valid, valid.length - 18);
    missingHash[1] = (byte) 0xA3;
    Assertions.assertArrayEquals(
      new byte[] { (byte) CTAP.MISSING_PARAMETER },
      command(missingHash)
    );

    byte[] missingY = Arrays.copyOf(point, point.length - 35);
    missingY[0] = (byte) 0xA4;
    Assertions.assertArrayEquals(
      new byte[] { (byte) CTAP.MISSING_PARAMETER },
      command(tokenRequest(missingY, hash))
    );

    byte[] invalidAlgorithm = point.clone();
    invalidAlgorithm[5] = 0x19;
    Assertions.assertArrayEquals(
      new byte[] { (byte) CTAP.INVALID_PARAMETER },
      command(tokenRequest(invalidAlgorithm, hash))
    );

    byte[] duplicateX = concatenate(point, Arrays.copyOfRange(point, 8, 43));
    duplicateX[0] = (byte) 0xA6;
    Assertions.assertArrayEquals(
      new byte[] { (byte) CTAP.INVALID_CBOR },
      command(tokenRequest(duplicateX, hash))
    );

    Assertions.assertArrayEquals(
      new byte[] { (byte) CTAP.INVALID_LENGTH },
      command(tokenRequest(point, Arrays.copyOf(hash, 15)))
    );
    Assertions.assertEquals(8, clientPIN.getRetries());
    Assertions.assertArrayEquals(host.authenticatorPublicKey, publicKey());
    Assertions.assertEquals(0, command(valid)[0]);
  }

  @Test
  public void reusedAuthenticatorPINProofPreservesWrongLengthAndEmptyProofSemantics()
    throws Exception {
    initializeCommands();
    assertError(CTAP.PIN_NOT_SET, () -> verifyAuthenticatorPIN(new byte[15], CLIENT_DATA_HASH));
    Assertions.assertEquals(8, clientPIN.getRetries());
    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    byte[] token = host.getToken(PIN);
    Assertions.assertTrue(verifyAuthenticatorPIN(auth(token, CLIENT_DATA_HASH), CLIENT_DATA_HASH));
    byte[] nextHash = new byte[32];
    Arrays.fill(nextHash, (byte) 0x5A);
    Assertions.assertTrue(verifyAuthenticatorPIN(auth(token, nextHash), nextHash));

    assertError(CTAP.PIN_INVALID, () -> verifyAuthenticatorPIN(new byte[0], CLIENT_DATA_HASH));
    assertError(CTAP.PIN_AUTH_INVALID, () ->
      verifyAuthenticatorPIN(new byte[15], CLIENT_DATA_HASH)
    );
    assertError(CTAP.PIN_AUTH_INVALID, () ->
      verifyAuthenticatorPIN(new byte[17], CLIENT_DATA_HASH)
    );
    assertError(CTAP.PIN_INVALID, () -> verifyAuthenticatorPIN(new byte[0], CLIENT_DATA_HASH));
    assertError(CTAP.PIN_AUTH_BLOCKED, () ->
      verifyAuthenticatorPIN(new byte[15], CLIENT_DATA_HASH)
    );
    assertError(CTAP.PIN_AUTH_BLOCKED, () ->
      verifyAuthenticatorPIN(auth(token, CLIENT_DATA_HASH), CLIENT_DATA_HASH)
    );
    Assertions.assertEquals(8, clientPIN.getRetries());
  }

  @Test
  public void exchangesPINAndTokenWithIndependentJCEClient() throws Exception {
    Assertions.assertFalse(clientPIN.isSet());
    Assertions.assertEquals(8, clientPIN.getRetries());
    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    Assertions.assertTrue(clientPIN.isSet());
    byte[] token = host.getToken(PIN);
    Assertions.assertEquals(32, token.length);
    clientPIN.verify(auth(token, CLIENT_DATA_HASH), CLIENT_DATA_HASH);

    byte[] next = new Host(clientPIN).getToken(PIN);
    Assertions.assertArrayEquals(token, next);
    Assertions.assertArrayEquals(host.authenticatorPublicKey, publicKey());
    clientPIN.deselect();
    clientPIN.verify(auth(token, CLIENT_DATA_HASH), CLIENT_DATA_HASH);
    Assertions.assertArrayEquals(host.authenticatorPublicKey, publicKey());
  }

  @Test
  public void reselectionClearsOnlyCommandScratchAndPreservesSessionCredentials() throws Exception {
    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    byte[] token = host.getToken(PIN);
    short[] session = (short[]) field("session").get(clientPIN);
    short[] previousSession = session.clone();
    Assertions.assertEquals(JCSystem.CLEAR_ON_RESET, JCSystem.isTransient(session));
    Assertions.assertEquals(
      JCSystem.CLEAR_ON_RESET,
      JCSystem.isTransient(field("token").get(clientPIN))
    );
    String[] scratchFields = { "sharedSecret", "workspace", "hmacBlock", "receivedAuth" };
    for (String name : scratchFields) {
      byte[] scratch = (byte[]) field(name).get(clientPIN);
      Assertions.assertEquals(JCSystem.CLEAR_ON_DESELECT, JCSystem.isTransient(scratch), name);
      Arrays.fill(scratch, (byte) 0x5A);
    }
    AESKey encryptionKey = (AESKey) field("encryptionKey").get(clientPIN);
    Assertions.assertEquals(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, encryptionKey.getType());
    Assertions.assertTrue(encryptionKey.isInitialized());

    reselect();

    for (String name : scratchFields) {
      byte[] scratch = (byte[]) field(name).get(clientPIN);
      Assertions.assertArrayEquals(new byte[scratch.length], scratch, name);
    }
    Assertions.assertFalse(encryptionKey.isInitialized());
    Assertions.assertArrayEquals(previousSession, session);
    Assertions.assertArrayEquals(token, (byte[]) field("token").get(clientPIN));
    Assertions.assertArrayEquals(host.authenticatorPublicKey, publicKey());
    clientPIN.verify(auth(token, CLIENT_DATA_HASH), CLIENT_DATA_HASH);
    Assertions.assertArrayEquals(token, host.getToken(PIN));
    host.changePIN(PIN, NEXT_PIN);
    byte[] nextToken = host.getToken(NEXT_PIN);
    Assertions.assertFalse(Arrays.equals(token, nextToken));
    clientPIN.verify(auth(nextToken, CLIENT_DATA_HASH), CLIENT_DATA_HASH);
  }

  @Test
  public void reselectionDoesNotRenewThePINFailureBudget() throws Exception {
    new Host(clientPIN).setPIN(PIN);
    for (int attempt = 0; attempt < 2; attempt++) {
      Host host = new Host(clientPIN);
      assertError(CTAP.PIN_INVALID, () -> host.getToken(WRONG_PIN));
    }
    Assertions.assertEquals(6, clientPIN.getRetries());

    reselect();

    Host host = new Host(clientPIN);
    assertError(CTAP.PIN_AUTH_BLOCKED, () -> host.getToken(WRONG_PIN));
    Assertions.assertEquals(5, clientPIN.getRetries());
    reselect();
    Host blocked = new Host(clientPIN);
    assertError(CTAP.PIN_AUTH_BLOCKED, () -> blocked.getToken(PIN));
    Assertions.assertEquals(5, clientPIN.getRetries());
  }

  @Test
  public void reselectionDoesNotRenewTheTokenProofFailureBudget() throws Exception {
    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    byte[] valid = auth(host.getToken(PIN), CLIENT_DATA_HASH);
    byte[] invalid = valid.clone();
    invalid[0] ^= 1;
    for (int attempt = 0; attempt < 2; attempt++) {
      assertError(CTAP.PIN_AUTH_INVALID, () -> clientPIN.verify(invalid, CLIENT_DATA_HASH));
    }

    reselect();

    assertError(CTAP.PIN_AUTH_BLOCKED, () -> clientPIN.verify(invalid, CLIENT_DATA_HASH));
    reselect();
    assertError(CTAP.PIN_AUTH_BLOCKED, () -> clientPIN.verify(valid, CLIENT_DATA_HASH));
    Assertions.assertEquals(8, clientPIN.getRetries());
  }

  @Test
  public void rejectsTamperedSetAndChangeBeforeConsumingPINRetries() throws Exception {
    Host host = new Host(clientPIN);
    byte[] encrypted = host.encrypt(Arrays.copyOf(PIN, 64));
    byte[] signature = auth(host.secret, encrypted);
    signature[0] ^= 1;
    assertError(CTAP.PIN_AUTH_INVALID, () ->
      clientPIN.setPIN(host.publicKey, signature, encrypted)
    );
    Assertions.assertFalse(clientPIN.isSet());
    host.setPIN(PIN);
    byte[] oldHash = host.encrypt(pinHash(PIN));
    byte[] next = host.encrypt(Arrays.copyOf(NEXT_PIN, 64));
    byte[] changeAuth = auth(host.secret, concatenate(next, oldHash));
    oldHash[0] ^= 1;
    assertError(CTAP.PIN_AUTH_INVALID, () ->
      clientPIN.changePIN(host.publicKey, changeAuth, next, oldHash)
    );
    Assertions.assertEquals(8, clientPIN.getRetries());
    host.getToken(PIN);
    assertError(CTAP.PIN_AUTH_INVALID, () -> host.setPIN(NEXT_PIN));
  }

  @Test
  public void failedPINRotatesECDHAndSuccessfulPINClearsConsecutiveFailures() throws Exception {
    new Host(clientPIN).setPIN(PIN);
    Host first = new Host(clientPIN);
    assertError(CTAP.PIN_INVALID, () -> first.getToken(WRONG_PIN));
    Assertions.assertEquals(7, clientPIN.getRetries());
    Assertions.assertFalse(Arrays.equals(first.authenticatorPublicKey, publicKey()));
    Host second = new Host(clientPIN);
    assertError(CTAP.PIN_INVALID, () -> second.getToken(WRONG_PIN));
    Assertions.assertEquals(6, clientPIN.getRetries());
    new Host(clientPIN).getToken(PIN);
    Assertions.assertEquals(8, clientPIN.getRetries());
    Host next = new Host(clientPIN);
    assertError(CTAP.PIN_INVALID, () -> next.getToken(WRONG_PIN));
    Assertions.assertEquals(7, clientPIN.getRetries());
  }

  @Test
  public void blocksAfterThreeErrorsUntilPowerCycleAndAfterEightUntilFIDOReset() throws Exception {
    new Host(clientPIN).setPIN(PIN);

    for (int attempt = 1; attempt <= 8; attempt++) {
      Host host = new Host(clientPIN);
      short expected = attempt == 8
        ? CTAP.PIN_BLOCKED
        : attempt % 3 == 0 ? CTAP.PIN_AUTH_BLOCKED : CTAP.PIN_INVALID;
      assertError(expected, () -> host.getToken(WRONG_PIN));
      Assertions.assertEquals(8 - attempt, clientPIN.getRetries());

      if (attempt % 3 == 0) {
        clientPIN.deselect();
        Host blocked = new Host(clientPIN);
        assertError(CTAP.PIN_AUTH_BLOCKED, () -> blocked.getToken(PIN));
        Assertions.assertEquals(8 - attempt, clientPIN.getRetries());
        simulator.reset();
      }
    }

    simulator.reset();
    Host blocked = new Host(clientPIN);
    assertError(CTAP.PIN_BLOCKED, () -> blocked.getToken(PIN));
    assertError(CTAP.PIN_BLOCKED, () -> blocked.changePIN(PIN, NEXT_PIN));
    clientPIN.reset();
    Assertions.assertFalse(clientPIN.isSet());
    Assertions.assertEquals(8, clientPIN.getRetries());
    new Host(clientPIN).setPIN(NEXT_PIN);
    new Host(clientPIN).getToken(NEXT_PIN);
  }

  @Test
  public void tokenAuthFailuresBlockWithoutSpendingPersistentPINRetries() throws Exception {
    new Host(clientPIN).setPIN(PIN);
    byte[] token = new Host(clientPIN).getToken(PIN);
    byte[] previousPublicKey = publicKey();
    byte[] valid = auth(token, CLIENT_DATA_HASH);
    byte[] invalid = valid.clone();
    invalid[15] ^= 1;
    assertError(CTAP.PIN_AUTH_INVALID, () -> clientPIN.verify(invalid, CLIENT_DATA_HASH));
    clientPIN.verify(valid, CLIENT_DATA_HASH);

    for (int attempt = 1; attempt <= 3; attempt++) {
      assertError(attempt == 3 ? CTAP.PIN_AUTH_BLOCKED : CTAP.PIN_AUTH_INVALID, () ->
        clientPIN.verify(invalid, CLIENT_DATA_HASH)
      );
    }

    Assertions.assertEquals(8, clientPIN.getRetries());
    clientPIN.deselect();
    assertError(CTAP.PIN_AUTH_BLOCKED, () -> clientPIN.verify(valid, CLIENT_DATA_HASH));
    simulator.reset();
    assertError(CTAP.PIN_AUTH_INVALID, () -> clientPIN.verify(valid, CLIENT_DATA_HASH));
    Assertions.assertFalse(Arrays.equals(previousPublicKey, publicKey()));
    byte[] next = new Host(clientPIN).getToken(PIN);
    Assertions.assertFalse(Arrays.equals(token, next));
    clientPIN.verify(auth(next, CLIENT_DATA_HASH), CLIENT_DATA_HASH);
  }

  @Test
  public void changingPINRequiresOldPINAndInvalidatesItsToken() throws Exception {
    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    byte[] token = host.getToken(PIN);
    assertError(CTAP.PIN_INVALID, () -> host.changePIN(WRONG_PIN, NEXT_PIN));
    Host correct = new Host(clientPIN);
    correct.changePIN(PIN, NEXT_PIN);
    Assertions.assertEquals(8, clientPIN.getRetries());
    assertError(CTAP.PIN_AUTH_INVALID, () ->
      clientPIN.verify(auth(token, CLIENT_DATA_HASH), CLIENT_DATA_HASH)
    );
    byte[] nextToken = new Host(clientPIN).getToken(NEXT_PIN);
    Assertions.assertFalse(Arrays.equals(token, nextToken));
    clientPIN.verify(auth(nextToken, CLIENT_DATA_HASH), CLIENT_DATA_HASH);
    Host old = new Host(clientPIN);
    assertError(CTAP.PIN_INVALID, () -> old.getToken(PIN));
  }

  @Test
  public void changingPINWorksWhenTheRotatedECDHScalarHasFewerBytes() throws Exception {
    javacard.security.KeyPair pair = (javacard.security.KeyPair) field("keyAgreement").get(
      clientPIN
    );
    Field implementationField = javacard.security.KeyPair.class.getDeclaredField("impl");
    implementationField.setAccessible(true);
    Object implementation = implementationField.get(pair);
    Field randomField = implementation.getClass().getDeclaredField("rnd");
    randomField.setAccessible(true);
    int[] generated = { 0 };
    randomField.set(
      implementation,
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Assertions.assertEquals(32, bytes.length);
          Arrays.fill(bytes, (byte) 0x55);
          if (generated[0]++ != 0) {
            bytes[0] = 0;
          }
        }
      }
    );

    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    assertError(CTAP.PIN_INVALID, () -> host.changePIN(WRONG_PIN, NEXT_PIN));
    Assertions.assertEquals(2, generated[0]);
    Host rotated = new Host(clientPIN);
    rotated.changePIN(PIN, NEXT_PIN);
    byte[] token = rotated.getToken(NEXT_PIN);
    clientPIN.verify(auth(token, CLIENT_DATA_HASH), CLIENT_DATA_HASH);
  }

  @Test
  public void invalidNewPINDoesNotReplaceCurrentPIN() throws Exception {
    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    assertError(CTAP.PIN_POLICY_VIOLATION, () ->
      host.changePIN(PIN, "abc".getBytes(StandardCharsets.UTF_8))
    );
    Assertions.assertEquals(8, clientPIN.getRetries());
    host.getToken(PIN);
  }

  @Test
  public void acceptsFourUnicodeCodepointsAndSixtyThreeBytes() throws Exception {
    byte[][] valid = {
      "1234".getBytes(StandardCharsets.UTF_8),
      "\u56DB\u4E2A\u6C49\u5B57".getBytes(StandardCharsets.UTF_8),
      "\uD83D\uDE00\uD83D\uDE01\uD83D\uDE02\uD83D\uDE03".getBytes(StandardCharsets.UTF_8),
      "A".repeat(63).getBytes(StandardCharsets.UTF_8),
    };

    for (byte[] value : valid) {
      clientPIN.reset();
      Host host = new Host(clientPIN);
      host.setPIN(value);
      byte[] token = host.getToken(value);
      clientPIN.verify(auth(token, CLIENT_DATA_HASH), CLIENT_DATA_HASH);
    }
  }

  @Test
  public void rejectsShortOverlongAndMalformedUTF8PINs() throws Exception {
    byte[][] invalid = {
      new byte[0],
      "123".getBytes(StandardCharsets.UTF_8),
      "\uD83D\uDE00".getBytes(StandardCharsets.UTF_8),
      "A".repeat(64).getBytes(StandardCharsets.UTF_8),
      { '1', '2', '3', (byte) 0xC0, (byte) 0xAF },
      { '1', '2', '3', (byte) 0xE0, (byte) 0x80, (byte) 0x80 },
      { '1', '2', '3', (byte) 0xED, (byte) 0xA0, (byte) 0x80 },
      { '1', '2', '3', (byte) 0xF4, (byte) 0x90, (byte) 0x80, (byte) 0x80 },
      { '1', '2', '3', (byte) 0xE1, (byte) 0x80 },
      { '1', '2', '3', (byte) 0x80 },
    };

    for (byte[] value : invalid) {
      Host host = new Host(clientPIN);
      assertError(CTAP.PIN_POLICY_VIOLATION, () -> host.setPIN(value));
      Assertions.assertFalse(clientPIN.isSet());
      Assertions.assertEquals(8, clientPIN.getRetries());
    }
  }

  @Test
  public void acceptsLongerZeroPaddingWithoutChangingThePINHash() throws Exception {
    Host host = new Host(clientPIN);
    byte[] encrypted = host.encrypt(Arrays.copyOf(PIN, 80));
    clientPIN.setPIN(host.publicKey, auth(host.secret, encrypted), encrypted);
    host.getToken(PIN);
  }

  @Test
  public void rejectsUninitializedPINAndMalformedProtocolInputs() throws Exception {
    Host host = new Host(clientPIN);
    assertError(CTAP.PIN_NOT_SET, () -> host.getToken(PIN));
    assertError(CTAP.PIN_NOT_SET, () -> host.changePIN(PIN, NEXT_PIN));
    assertError(CTAP.PIN_NOT_SET, () -> clientPIN.verify(new byte[16], CLIENT_DATA_HASH));
    byte[] padded = host.encrypt(Arrays.copyOf(PIN, 64));
    assertError(CTAP.INVALID_PARAMETER, () ->
      clientPIN.setPIN(new byte[65], auth(host.secret, padded), padded)
    );
    host.setPIN(PIN);
    assertError(CTAP.INVALID_LENGTH, () ->
      clientPIN.getPINToken(host.publicKey, new byte[15], new byte[32], (short) 0)
    );
    assertError(CTAP.PIN_AUTH_INVALID, () -> clientPIN.verify(new byte[15], CLIENT_DATA_HASH));
    Assertions.assertEquals(8, clientPIN.getRetries());
  }

  @Test
  public void booleanSuccessCannotAuthorizeAnUnvalidatedOwnerPIN() throws Exception {
    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    OwnerPIN observed = new OwnerPIN((byte) 8, (byte) 16) {
      @Override
      public boolean check(byte[] value, short offset, byte length) {
        super.check(value, offset, length);
        return true;
      }
    };
    observed.update(pinHash(PIN), (short) 0, (byte) 16);
    field("pin").set(clientPIN, observed);
    assertError(CTAP.PIN_AUTH_INVALID, () -> host.getToken(WRONG_PIN));
    Assertions.assertEquals(7, clientPIN.getRetries());
  }

  @Test
  public void everyNativeValidationReadMustSucceed() throws Exception {
    Host host = new Host(clientPIN);
    host.setPIN(PIN);

    for (int failure = 1; failure <= 6; failure++) {
      int failedRead = failure;
      int[] reads = { 0 };
      OwnerPIN observed = new OwnerPIN((byte) 8, (byte) 16) {
        @Override
        public boolean isValidated() {
          return super.isValidated() && ++reads[0] != failedRead;
        }
      };
      observed.update(pinHash(PIN), (short) 0, (byte) 16);
      field("pin").set(clientPIN, observed);
      assertError(CTAP.PIN_AUTH_INVALID, () -> host.getToken(PIN));
    }
  }

  @Test
  public void invalidPINStateDoesNotPermitInitialization() throws Exception {
    Host host = new Host(clientPIN);
    field("pinState").setShort(clientPIN, (short) (Constants.SAFE_FALSE ^ 1));
    assertError(CTAP.OTHER, clientPIN::isSet);
    assertError(CTAP.OTHER, () -> host.setPIN(PIN));
  }

  @Test
  public void resetClearsPINAndRotatesSessionCredentials() throws Exception {
    Host host = new Host(clientPIN);
    host.setPIN(PIN);
    byte[] token = host.getToken(PIN);
    clientPIN.reset();
    Assertions.assertFalse(clientPIN.isSet());
    assertError(CTAP.PIN_NOT_SET, () ->
      clientPIN.verify(auth(token, CLIENT_DATA_HASH), CLIENT_DATA_HASH)
    );
    Host next = new Host(clientPIN);
    Assertions.assertFalse(Arrays.equals(host.authenticatorPublicKey, next.authenticatorPublicKey));
    next.setPIN(NEXT_PIN);
    Assertions.assertFalse(Arrays.equals(token, next.getToken(NEXT_PIN)));
  }

  @Test
  public void resetCanBeRepeatedBeforeSettingAnotherPIN() throws Exception {
    new Host(clientPIN).setPIN(PIN);
    clientPIN.reset();
    clientPIN.reset();
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
    Assertions.assertFalse(clientPIN.isSet());
    Assertions.assertEquals(8, clientPIN.getRetries());

    new Host(clientPIN).setPIN(NEXT_PIN);
    new Host(clientPIN).getToken(NEXT_PIN);
  }

  private byte[] publicKey() {
    byte[] result = new byte[65];
    Assertions.assertEquals(65, clientPIN.getKeyAgreement(result, (short) 0));
    return result;
  }

  private void initializeCommands() {
    simulator.installApplet(AIDUtil.create(COMMAND_APPLET_AID), ClientPINCommandApplet.class);
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(COMMAND_APPLET_AID)));
    clientPIN = Command.authenticator.pin;
  }

  private boolean verifyAuthenticatorPIN(byte[] proof, byte[] clientDataHash) {
    byte[] data = concatenate(
      concatenate(new byte[] { (byte) 0xA2, 6, (byte) (0x40 + proof.length) }, proof),
      new byte[] { 7, 1 }
    );
    CBORReader reader = new CBORReader(data, (short) 0, (short) data.length);
    CBORMap fields = reader.map(new short[] { 6, 7 });
    return Command.authenticator.verifyPIN(
      fields,
      reader,
      (short) 6,
      (short) 7,
      clientDataHash,
      false
    );
  }

  private byte[] command(byte[] request) {
    ResponseAPDU response = simulator.transmitCommand(
      new CommandAPDU(0x80, 0x10, 0, 0, request, 17)
    );
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    while (true) {
      byte[] chunk = response.getData();
      output.write(chunk, 0, chunk.length);
      if (response.getSW1() != 0x61) {
        Assertions.assertEquals(0x9000, response.getSW());
        return output.toByteArray();
      }
      response = simulator.transmitCommand(new CommandAPDU(0, 0xC0, 0, 0, 17));
    }
  }

  private static byte[] cose(byte[] point) {
    return concatenate(
      concatenate(
        new byte[] { (byte) 0xA5, 1, 2, 3, 0x38, 0x18, 0x20, 1, 0x21, 0x58, 0x20 },
        Arrays.copyOfRange(point, 1, 33)
      ),
      concatenate(new byte[] { 0x22, 0x58, 0x20 }, Arrays.copyOfRange(point, 33, 65))
    );
  }

  private static byte[] tokenRequest(byte[] point, byte[] hash) {
    return concatenate(
      concatenate(new byte[] { 6, (byte) 0xA4, 1, 1, 2, 5, 3 }, point),
      concatenate(new byte[] { 6, (byte) (0x40 + hash.length) }, hash)
    );
  }

  private void reselect() {
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(OTHER_APPLET_AID)));
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(PIN_APPLET_AID)));
  }

  public static final class PINApplet extends Applet {

    private static PINApplet installed;
    private final ClientPIN clientPIN = new ClientPIN();

    public static void install(byte[] buffer, short offset, byte length) {
      installed = new PINApplet();
      installed.register();
    }

    @Override
    public void deselect() {
      clientPIN.deselect();
    }

    @Override
    public void process(APDU apdu) {}
  }

  public static final class OtherApplet extends Applet {

    public static void install(byte[] buffer, short offset, byte length) {
      new OtherApplet().register();
    }

    @Override
    public void process(APDU apdu) {}
  }

  public static final class ClientPINCommandApplet extends Applet {

    private final ApduTransport transport = new ApduTransport();

    public static void install(byte[] buffer, short offset, byte length) {
      Command.init();
      new ClientPINCommandApplet().register();
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        transport.clear();
        return;
      }
      transport.process(apdu);
    }

    @Override
    public void deselect() {
      transport.clear();
      Command.clear();
    }
  }

  private static Field field(String name) throws Exception {
    Field result = ClientPIN.class.getDeclaredField(name);
    result.setAccessible(true);
    return result;
  }

  private static void assertError(short code, Executable operation) {
    ISOException exception = Assertions.assertThrows(ISOException.class, operation);
    Assertions.assertEquals(code, exception.getReason());
  }

  private static byte[] pinHash(byte[] pin) throws Exception {
    return Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(pin), 16);
  }

  private static byte[] auth(byte[] key, byte[] data) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    return Arrays.copyOf(mac.doFinal(data), 16);
  }

  private static byte[] concatenate(byte[] first, byte[] second) {
    byte[] result = Arrays.copyOf(first, first.length + second.length);
    System.arraycopy(second, 0, result, first.length, second.length);
    return result;
  }

  static final class Host {

    private final ClientPIN clientPIN;
    private final byte[] authenticatorPublicKey = new byte[65];
    private final byte[] publicKey = new byte[65];
    private final byte[] secret;

    Host(ClientPIN clientPIN) throws Exception {
      this.clientPIN = clientPIN;
      clientPIN.getKeyAgreement(authenticatorPublicKey, (short) 0);
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp256r1"));
      KeyPair pair = generator.generateKeyPair();
      ECPublicKey own = (ECPublicKey) pair.getPublic();
      publicKey[0] = 4;
      coordinate(own.getW().getAffineX(), publicKey, 1);
      coordinate(own.getW().getAffineY(), publicKey, 33);
      ECPoint point = new ECPoint(
        new BigInteger(1, Arrays.copyOfRange(authenticatorPublicKey, 1, 33)),
        new BigInteger(1, Arrays.copyOfRange(authenticatorPublicKey, 33, 65))
      );
      KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
      agreement.init(pair.getPrivate());
      agreement.doPhase(
        KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, own.getParams())),
        true
      );
      secret = MessageDigest.getInstance("SHA-256").digest(agreement.generateSecret());
    }

    void setPIN(byte[] pin) throws Exception {
      byte[] encrypted = encrypt(Arrays.copyOf(pin, 64));
      clientPIN.setPIN(publicKey, auth(secret, encrypted), encrypted);
    }

    private void changePIN(byte[] current, byte[] next) throws Exception {
      byte[] encrypted = encrypt(Arrays.copyOf(next, 64));
      byte[] encryptedHash = encrypt(pinHash(current));
      clientPIN.changePIN(
        publicKey,
        auth(secret, concatenate(encrypted, encryptedHash)),
        encrypted,
        encryptedHash
      );
    }

    byte[] getToken(byte[] pin) throws Exception {
      byte[] dest = new byte[35];
      Arrays.fill(dest, (byte) 0x7E);
      Assertions.assertEquals(
        32,
        clientPIN.getPINToken(publicKey, encrypt(pinHash(pin)), dest, (short) 2)
      );
      Assertions.assertEquals(0x7E, dest[0]);
      Assertions.assertEquals(0x7E, dest[1]);
      Assertions.assertEquals(0x7E, dest[34]);
      return crypt(Cipher.DECRYPT_MODE, Arrays.copyOfRange(dest, 2, 34));
    }

    private byte[] encrypt(byte[] data) throws Exception {
      return crypt(Cipher.ENCRYPT_MODE, data);
    }

    private byte[] crypt(int mode, byte[] data) throws Exception {
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(mode, new SecretKeySpec(secret, "AES"), new IvParameterSpec(new byte[16]));
      return cipher.doFinal(data);
    }

    private static void coordinate(BigInteger value, byte[] dest, int offset) {
      byte[] bytes = value.toByteArray();
      int length = Math.min(32, bytes.length);
      System.arraycopy(bytes, bytes.length - length, dest, offset + 32 - length, length);
    }
  }
}
