package monoididentity;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoid.CBORBufferReader;
import monoid.MonoidApplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tests.AppletTest;
import tests.IdentityCallerApplet;

public class MonoidIdentityAppletTest {

  private static final AID IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_IDENTITY_AID}}"
    "f06d6f6e6f69640001"
  );
  private static final AID OTHER_IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_NAMESPACE}}7f12"
    "f06d6f6e6f69647f12"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );
  private static final AID MONOID_CALLER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_NAMESPACE}}7f11"
    "f06d6f6e6f69647f11"
  );
  private static final AID UNRELATED_AID = AIDUtil.create("f06d6f6e6f69647f13");

  private static final byte[] CONTEXT = "card transfer".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] PIN = "888888".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] NEW_PIN = "123456".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] KEY = "0123456789ABCDEF0123456789ABCDEF".getBytes(
    StandardCharsets.US_ASCII
  );

  private TokenRuntime runtime;
  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    runtime = new TokenRuntime();
    simulator = new CardSimulator(runtime);
    simulator.installApplet(IDENTITY_AID, MonoidIdentityApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    simulator.installApplet(MONOID_CALLER_AID, IdentityCallerApplet.class);
    simulator.installApplet(UNRELATED_AID, IdentityCallerApplet.class);
    select(MONOID_CALLER_AID);
  }

  @Test
  public void unrelatedCallersCanAcquireIdentityAndReadPublicInformation() {
    Assertions.assertArrayEquals(new byte[] { 0 }, acquire(IDENTITY_AID));
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    Assertions.assertEquals(65, publicKey.length);
    Assertions.assertEquals(4, publicKey[0]);
    Assertions.assertEquals(4, success(transmit(IdentityCallerApplet.GET_IDENTITY_ID)).length);

    select(UNRELATED_AID);
    acquire(IDENTITY_AID);
    Assertions.assertArrayEquals(publicKey, success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY)));
  }

  @Test
  public void repeatedAcquisitionAndCardResetKeepTheIdentity() {
    acquire(IDENTITY_AID);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] id = success(transmit(IdentityCallerApplet.GET_IDENTITY_ID));
    Assertions.assertArrayEquals(new byte[] { 1 }, acquire(IDENTITY_AID));
    Assertions.assertArrayEquals(publicKey, success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY)));
    Assertions.assertArrayEquals(id, success(transmit(IdentityCallerApplet.GET_IDENTITY_ID)));

    simulator.reset();
    select(MONOID_CALLER_AID);
    acquire(IDENTITY_AID);
    Assertions.assertArrayEquals(publicKey, success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY)));
    Assertions.assertArrayEquals(id, success(transmit(IdentityCallerApplet.GET_IDENTITY_ID)));
  }

  @Test
  public void returnedIdCopiesCannotChangeTheIdentity() {
    acquire(IDENTITY_AID);
    byte[] id = success(transmit(IdentityCallerApplet.GET_IDENTITY_ID));
    byte[] changed = id.clone();
    changed[0] ^= (byte) 0xFF;

    Assertions.assertArrayEquals(changed, success(transmit(IdentityCallerApplet.MUTATE_ID_COPY)));
    Assertions.assertArrayEquals(id, success(transmit(IdentityCallerApplet.GET_IDENTITY_ID)));
  }

  @Test
  public void secretPINRequiresExplicitVerificationAndUpdatesRevokeAuthorization() {
    initializeManager();
    acquire(IDENTITY_AID);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    assertSecretPINSet(false);
    assertSecretPINTries(5);
    checkSecretPIN(PIN, false);
    assertSecretPINTries(5);
    assertDenied(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));
    assertDenied(transmit(IdentityCallerApplet.CREATE_BUNDLE, publicKey));
    assertDenied(transmit(IdentityCallerApplet.JOIN_BUNDLE, publicKey));

    success(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, PIN));
    assertSecretPINSet(true);
    assertSecretValidation(false);
    assertDenied(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));
    assertDenied(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, NEW_PIN));
    checkSecretPIN(PIN, true);
    byte[] encrypted = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY))
    );

    checkSecretPIN(NEW_PIN, false);
    assertSecretPINTries(4);
    assertDenied(
      transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encrypted))
    );
    assertDenied(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, NEW_PIN));
    checkSecretPIN(PIN, true);
    assertSecretPINTries(5);
    success(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, NEW_PIN));
    assertSecretValidation(false);
    assertDenied(
      transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encrypted))
    );
    checkSecretPIN(PIN, false);
    assertSecretPINTries(4);
    checkSecretPIN(NEW_PIN, true);
    assertSecretPINTries(5);
    Assertions.assertArrayEquals(
      KEY,
      success(transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encrypted)))
    );

    success(transmit(IdentityCallerApplet.CLEAR_SECRET_AUTH));
    assertSecretValidation(false);
    assertSecretPINSet(true);
    assertSecretPINTries(5);
    assertDenied(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));
    checkSecretPIN(NEW_PIN, true);
  }

  @Test
  public void secretAuthorizationBelongsToTheVerifiedCallerAndCannotAuthorizePinUpdates() {
    initializeManager();
    acquire(IDENTITY_AID);
    initializeSecretPIN();
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    select(UNRELATED_AID);
    acquire(IDENTITY_AID);
    assertSecretValidation(false);
    assertDenied(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));
    assertDenied(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, NEW_PIN));

    select(MONOID_AID);
    assertSecretValidation(true);
    acquire(IDENTITY_AID);
    assertSecretValidation(true);
    select(UNRELATED_AID);
    checkSecretPIN(PIN, true);
    success(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));
    assertDenied(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, NEW_PIN));
    assertDenied(transmit(IdentityCallerApplet.CREATE_BUNDLE, publicKey));
    assertDenied(transmit(IdentityCallerApplet.JOIN_BUNDLE, publicKey));

    select(MONOID_AID);
    assertSecretValidation(false);
    assertDenied(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, NEW_PIN));
    assertDenied(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));
    checkSecretPIN(NEW_PIN, false);
    select(UNRELATED_AID);
    assertSecretValidation(false);
    assertDenied(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));
    select(MONOID_AID);
    checkSecretPIN(PIN, true);
  }

  @Test
  public void replacingMonoidRetainsTheSecretPINAndRequiresItsVerification() {
    initializeManager();
    acquire(IDENTITY_AID);
    initializeSecretPIN();
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] token = success(transmit(IdentityCallerApplet.GET_TOKEN));
    byte[] encrypted = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY))
    );

    select(IDENTITY_AID);
    simulator.deleteApplet(MONOID_AID);
    AID replacement = AIDUtil.create(AppletTest.aidBytes(MONOID_AID));
    simulator.createApplet(replacement, new byte[0], (short) 0, (byte) 0);
    select(replacement);
    acquire(IDENTITY_AID);
    Assertions.assertArrayEquals(token, success(transmit(IdentityCallerApplet.GET_TOKEN)));
    Assertions.assertArrayEquals(publicKey, success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY)));
    assertSecretPINSet(true);
    assertSecretValidation(false);
    assertDenied(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, NEW_PIN));
    assertDenied(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));
    assertDenied(
      transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encrypted))
    );
    checkSecretPIN(NEW_PIN, false);
    checkSecretPIN(PIN, true);
    Assertions.assertArrayEquals(
      KEY,
      success(transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encrypted)))
    );
  }

  @Test
  public void identityResetClearsBlockedSecretPINAndRequiresNewInitialization() {
    initializeManager();
    acquire(IDENTITY_AID);
    initializeSecretPIN();
    for (int remaining = 4; remaining >= 0; remaining--) {
      checkSecretPIN(NEW_PIN, false);
      assertSecretPINTries(remaining);
    }
    checkSecretPIN(PIN, false);
    assertSecretPINTries(0);
    assertDenied(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, NEW_PIN));

    success(transmit(IdentityCallerApplet.PREPARE_RESET));
    success(transmit(IdentityCallerApplet.RESET_IDENTITY));
    assertSecretPINSet(false);
    assertSecretValidation(false);
    assertSecretPINTries(5);
    checkSecretPIN(PIN, false);
    assertSecretPINTries(5);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    assertDenied(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));

    success(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, NEW_PIN));
    assertSecretValidation(false);
    checkSecretPIN(PIN, false);
    checkSecretPIN(NEW_PIN, true);
    success(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));
  }

  @Test
  public void forwardedIdentityUsesTheActualCallerForTokenAndDecryption() {
    initializeManager();
    acquire(IDENTITY_AID);
    initializeSecretPIN();
    select(MONOID_CALLER_AID);
    acquire(IDENTITY_AID);
    checkSecretPIN(PIN, true);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] token = success(transmit(IdentityCallerApplet.GET_TOKEN));
    byte[] encrypted = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY))
    );
    select(UNRELATED_AID);
    success(transmit(IdentityCallerApplet.BORROW_IDENTITY, AppletTest.aidBytes(MONOID_CALLER_AID)));

    Assertions.assertArrayEquals(publicKey, success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY)));
    Assertions.assertFalse(Arrays.equals(token, success(transmit(IdentityCallerApplet.GET_TOKEN))));
    assertSecretValidation(false);
    assertDenied(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));
    assertDenied(
      transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encrypted))
    );
    checkSecretPIN(PIN, true);
    ResponseAPDU denied = transmit(
      IdentityCallerApplet.DECRYPT_DATA,
      payload(publicKey, CONTEXT, encrypted)
    );
    Assertions.assertNotEquals(0x9000, denied.getSW());
    Assertions.assertEquals(0, denied.getData().length);

    byte[] ownEncrypted = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY))
    );
    Assertions.assertArrayEquals(
      KEY,
      success(
        transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, ownEncrypted))
      )
    );
  }

  @Test
  public void tokenComputationReadsTheCallerForEveryHmacInput() {
    acquire(IDENTITY_AID);
    runtime.callerReads = 0;
    success(transmit(IdentityCallerApplet.GET_TOKEN));

    // One admission check followed by three independent HMAC input reads.
    Assertions.assertEquals(4, runtime.callerReads);
  }

  @Test
  public void tokensMatchHostHmacWithThreeCallerAidInputs() throws Exception {
    Field secretField = MonoidIdentityApplet.class.getDeclaredField("tokenSecret");
    secretField.setAccessible(true);
    byte[] secret = (byte[]) secretField.get(runtime.lookupApplet(IDENTITY_AID).getApplet());
    byte[] context = "Monoid Identity Token".getBytes(StandardCharsets.US_ASCII);
    AID[] callers = {
      AIDUtil.create("f06d000001"),
      AIDUtil.create("f06d6f6e6f69647f"),
      MONOID_CALLER_AID,
      AIDUtil.create("f06d6f6e6f69647f1101020304050607"),
    };

    for (AID caller : callers) {
      if (caller != MONOID_CALLER_AID) {
        simulator.installApplet(caller, IdentityCallerApplet.class);
      }

      select(caller);
      acquire(IDENTITY_AID);
      byte[] token = success(transmit(IdentityCallerApplet.GET_TOKEN));
      byte[] aid = AppletTest.aidBytes(caller);
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(secret, "HmacSHA256"));
      mac.update(context);
      mac.update(aid);
      mac.update(aid);
      byte[] expected = mac.doFinal(aid);

      Assertions.assertArrayEquals(expected, token);
      Assertions.assertArrayEquals(expected, success(transmit(IdentityCallerApplet.GET_TOKEN)));

      mac.update(context);
      Assertions.assertFalse(Arrays.equals(mac.doFinal(aid), token));
    }
  }

  @Test
  public void tokensAreStablePrivateCopiesAndSeparatedByCallerAndIdentity() {
    acquire(IDENTITY_AID);
    byte[] token = success(transmit(IdentityCallerApplet.GET_TOKEN));
    Assertions.assertEquals(32, token.length);
    byte[] changed = token.clone();
    changed[0] ^= (byte) 0xFF;
    Assertions.assertArrayEquals(
      changed,
      success(transmit(IdentityCallerApplet.MUTATE_TOKEN_COPY))
    );
    Assertions.assertArrayEquals(token, success(transmit(IdentityCallerApplet.GET_TOKEN)));

    simulator.reset();
    select(MONOID_CALLER_AID);
    acquire(IDENTITY_AID);
    Assertions.assertArrayEquals(token, success(transmit(IdentityCallerApplet.GET_TOKEN)));

    select(UNRELATED_AID);
    acquire(IDENTITY_AID);
    Assertions.assertFalse(Arrays.equals(token, success(transmit(IdentityCallerApplet.GET_TOKEN))));

    simulator.installApplet(OTHER_IDENTITY_AID, MonoidIdentityApplet.class);
    select(MONOID_CALLER_AID);
    acquire(OTHER_IDENTITY_AID);
    Assertions.assertFalse(Arrays.equals(token, success(transmit(IdentityCallerApplet.GET_TOKEN))));
  }

  @Test
  public void alternatingCallersKeepTheirOwnTokens() {
    acquire(IDENTITY_AID);
    byte[] token = success(transmit(IdentityCallerApplet.GET_TOKEN));
    select(UNRELATED_AID);
    acquire(IDENTITY_AID);
    byte[] unrelatedToken = success(transmit(IdentityCallerApplet.GET_TOKEN));
    Assertions.assertFalse(Arrays.equals(token, unrelatedToken));

    for (int round = 0; round < 3; round++) {
      select(MONOID_CALLER_AID);
      Assertions.assertArrayEquals(token, success(transmit(IdentityCallerApplet.GET_TOKEN)));
      select(UNRELATED_AID);
      Assertions.assertArrayEquals(
        unrelatedToken,
        success(transmit(IdentityCallerApplet.GET_TOKEN))
      );
    }
  }

  @Test
  public void tokensUseTheCompleteCallerAidIncludingItsLength() {
    AID longerCaller = AIDUtil.create(
      concat(AppletTest.aidBytes(MONOID_CALLER_AID), new byte[] { 0 })
    );
    simulator.installApplet(longerCaller, IdentityCallerApplet.class);
    select(MONOID_CALLER_AID);
    acquire(IDENTITY_AID);
    byte[] token = success(transmit(IdentityCallerApplet.GET_TOKEN));
    select(longerCaller);
    acquire(IDENTITY_AID);
    byte[] longerToken = success(transmit(IdentityCallerApplet.GET_TOKEN));
    Assertions.assertFalse(Arrays.equals(token, longerToken));

    select(MONOID_CALLER_AID);
    Assertions.assertArrayEquals(token, success(transmit(IdentityCallerApplet.GET_TOKEN)));
    select(longerCaller);
    Assertions.assertArrayEquals(longerToken, success(transmit(IdentityCallerApplet.GET_TOKEN)));
  }

  @Test
  public void tokensRemainStableAfterMoreThanThirtyTwoCallers() {
    AID[] callers = new AID[40];
    byte[][] tokens = new byte[callers.length][];

    for (int index = 0; index < callers.length; index++) {
      callers[index] = AIDUtil.create(
        concat(AppletTest.aidBytes(MONOID_CALLER_AID), new byte[] { (byte) index })
      );
      simulator.installApplet(callers[index], IdentityCallerApplet.class);
      select(callers[index]);
      acquire(IDENTITY_AID);
      tokens[index] = success(transmit(IdentityCallerApplet.GET_TOKEN));

      for (int previous = 0; previous < index; previous++) {
        Assertions.assertFalse(Arrays.equals(tokens[previous], tokens[index]));
      }
    }

    for (int index = 0; index < callers.length; index++) {
      select(callers[index]);
      Assertions.assertArrayEquals(
        tokens[index],
        success(transmit(IdentityCallerApplet.GET_TOKEN))
      );
    }
  }

  @Test
  public void replacingACallerWithTheSameAidKeepsItsToken() {
    acquire(IDENTITY_AID);
    byte[] token = success(transmit(IdentityCallerApplet.GET_TOKEN));
    select(IDENTITY_AID);
    simulator.deleteApplet(MONOID_CALLER_AID);
    simulator.createApplet(MONOID_CALLER_AID, new byte[0], (short) 0, (byte) 0);
    select(MONOID_CALLER_AID);
    acquire(IDENTITY_AID);

    Assertions.assertArrayEquals(token, success(transmit(IdentityCallerApplet.GET_TOKEN)));
  }

  @Test
  public void tokensSurviveCallerTransactionAbortsBeforeAndAfterCaching() {
    acquire(IDENTITY_AID);
    byte[] token = success(transmit(IdentityCallerApplet.GET_TOKEN));
    Assertions.assertArrayEquals(
      token,
      success(transmit(IdentityCallerApplet.GET_TOKEN_ABORT_TRANSACTION))
    );
    Assertions.assertArrayEquals(token, success(transmit(IdentityCallerApplet.GET_TOKEN)));

    select(UNRELATED_AID);
    acquire(IDENTITY_AID);
    byte[] unrelatedToken = success(transmit(IdentityCallerApplet.GET_TOKEN_ABORT_TRANSACTION));
    Assertions.assertFalse(Arrays.equals(token, unrelatedToken));
    Assertions.assertArrayEquals(
      unrelatedToken,
      success(transmit(IdentityCallerApplet.GET_TOKEN_ABORT_TRANSACTION))
    );
    Assertions.assertArrayEquals(unrelatedToken, success(transmit(IdentityCallerApplet.GET_TOKEN)));
    Assertions.assertArrayEquals(
      unrelatedToken,
      success(transmit(IdentityCallerApplet.GET_TOKEN_ABORT_TRANSACTION))
    );
    Assertions.assertArrayEquals(unrelatedToken, success(transmit(IdentityCallerApplet.GET_TOKEN)));
  }

  @Test
  public void unrelatedAndPrefixCallersCannotManageBundleOrResetIdentity() {
    AID prefixCaller = AIDUtil.create(concat(AppletTest.aidBytes(MONOID_AID), new byte[] { 1 }));
    simulator.installApplet(prefixCaller, IdentityCallerApplet.class);

    for (AID caller : new AID[] { MONOID_CALLER_AID, UNRELATED_AID, prefixCaller }) {
      select(caller);
      acquire(IDENTITY_AID);
      byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
      assertDenied(transmit(IdentityCallerApplet.CREATE_BUNDLE, publicKey));
      assertDenied(transmit(IdentityCallerApplet.JOIN_BUNDLE, concat(publicKey, new byte[0])));
      assertDenied(transmit(IdentityCallerApplet.PREPARE_RESET));
      assertDenied(transmit(IdentityCallerApplet.RESET_IDENTITY));
      assertDenied(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, PIN));
      Assertions.assertEquals(0, success(transmit(IdentityCallerApplet.GET_BUNDLE)).length);
    }
  }

  @Test
  public void safeIdMatchesIdentityAndSurvivesMonoidReplacement() {
    acquire(IDENTITY_AID);
    byte[] id = success(transmit(IdentityCallerApplet.GET_IDENTITY_ID));
    Assertions.assertArrayEquals(id, safeId());

    select(IDENTITY_AID);
    simulator.deleteApplet(MONOID_AID);
    simulator.createApplet(MONOID_AID, new byte[0], (short) 0, (byte) 0);
    Assertions.assertArrayEquals(id, safeId());

    simulator.reset();
    Assertions.assertArrayEquals(id, safeId());
  }

  @Test
  public void replacingIdentityDoesNotRebindExistingMonoid() {
    acquire(IDENTITY_AID);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] id = safeId();

    simulator.deleteApplet(MONOID_CALLER_AID);
    simulator.deleteApplet(IDENTITY_AID);
    simulator.createApplet(IDENTITY_AID, new byte[0], (short) 0, (byte) 0);
    simulator.createApplet(MONOID_CALLER_AID, new byte[0], (short) 0, (byte) 0);

    select(MONOID_CALLER_AID);
    acquire(IDENTITY_AID);
    Assertions.assertFalse(
      Arrays.equals(publicKey, success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY)))
    );
    byte[] replacementId = success(transmit(IdentityCallerApplet.GET_IDENTITY_ID));
    Assertions.assertFalse(Arrays.equals(id, replacementId));
    select(MONOID_AID);
    assertDenied(transmit(0x20, new byte[] { (byte) 0xA0 }));
    simulator.reset();
    select(MONOID_AID);
    assertDenied(transmit(0x20, new byte[] { (byte) 0xA0 }));

    select(IDENTITY_AID);
    simulator.deleteApplet(MONOID_AID);
    simulator.createApplet(MONOID_AID, new byte[0], (short) 0, (byte) 0);
    Assertions.assertArrayEquals(replacementId, safeId());
  }

  @Test
  public void communicationDataCanBeRecoveredByTheSameIdentityAfterCardReset() {
    initializeManager();
    acquire(IDENTITY_AID);
    initializeSecretPIN();
    select(MONOID_CALLER_AID);
    acquire(IDENTITY_AID);
    checkSecretPIN(PIN, true);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] encryptedKey = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY))
    );
    Assertions.assertEquals(KEY.length + 144, encryptedKey.length);

    simulator.reset();
    select(MONOID_CALLER_AID);
    acquire(IDENTITY_AID);
    assertSecretPINSet(true);
    assertSecretValidation(false);
    assertDenied(
      transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encryptedKey))
    );
    checkSecretPIN(PIN, true);
    Assertions.assertArrayEquals(
      KEY,
      success(
        transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encryptedKey))
      )
    );
  }

  @Test
  public void communicationDataCanBeRecoveredByAnotherIdentity() {
    initializeManager();
    simulator.installApplet(OTHER_IDENTITY_AID, MonoidIdentityApplet.class);
    select(MONOID_AID);
    acquire(IDENTITY_AID);
    initializeSecretPIN();
    byte[] senderPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    acquire(OTHER_IDENTITY_AID);
    initializeSecretPIN();
    byte[] recipientPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    acquire(IDENTITY_AID);
    byte[] encryptedKey = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(recipientPublicKey, CONTEXT, KEY))
    );

    acquire(OTHER_IDENTITY_AID);
    Assertions.assertArrayEquals(
      KEY,
      success(
        transmit(IdentityCallerApplet.DECRYPT_DATA, payload(senderPublicKey, CONTEXT, encryptedKey))
      )
    );
  }

  @Test
  public void bundledTransfersRequireEachIdentitysPINAndCannotBeDecryptedByTheirSender() {
    initializeManager();
    acquire(IDENTITY_AID);
    initializeSecretPIN();
    byte[] sourcePublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] oldSelfTransfer = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(sourcePublicKey, CONTEXT, KEY))
    );

    simulator.installApplet(OTHER_IDENTITY_AID, MonoidIdentityApplet.class);
    select(MONOID_AID);
    acquire(OTHER_IDENTITY_AID);
    success(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, NEW_PIN));
    byte[] targetPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    acquire(IDENTITY_AID);
    success(transmit(IdentityCallerApplet.CLEAR_SECRET_AUTH));
    byte[] members = concat(sourcePublicKey, targetPublicKey);
    assertDenied(transmit(IdentityCallerApplet.CREATE_BUNDLE, members));
    checkSecretPIN(PIN, true);
    byte[] enrollment = success(transmit(IdentityCallerApplet.CREATE_BUNDLE, members));
    byte[] bundle = success(transmit(IdentityCallerApplet.GET_BUNDLE));
    byte[] encrypted = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(sourcePublicKey, CONTEXT, KEY))
    );
    Assertions.assertEquals(2, encrypted[0]);
    Assertions.assertArrayEquals(sourcePublicKey, Arrays.copyOfRange(encrypted, 33, 98));
    for (byte[] ciphertext : new byte[][] { oldSelfTransfer, encrypted }) {
      Assertions.assertEquals(
        0x6985,
        transmit(
          IdentityCallerApplet.DECRYPT_DATA,
          payload(sourcePublicKey, CONTEXT, ciphertext)
        ).getSW()
      );
    }

    acquire(OTHER_IDENTITY_AID);
    byte[] join = concat(sourcePublicKey, enrollment);
    assertDenied(transmit(IdentityCallerApplet.JOIN_BUNDLE, join));
    checkSecretPIN(NEW_PIN, true);
    Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.JOIN_BUNDLE, join)));
    success(transmit(IdentityCallerApplet.CLEAR_SECRET_AUTH));
    assertDenied(
      transmit(IdentityCallerApplet.DECRYPT_DATA, payload(sourcePublicKey, CONTEXT, encrypted))
    );
    checkSecretPIN(PIN, false);
    checkSecretPIN(NEW_PIN, true);
    Assertions.assertArrayEquals(
      KEY,
      success(
        transmit(IdentityCallerApplet.DECRYPT_DATA, payload(sourcePublicKey, CONTEXT, encrypted))
      )
    );
    byte[] reply = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(sourcePublicKey, CONTEXT, KEY))
    );
    Assertions.assertArrayEquals(targetPublicKey, Arrays.copyOfRange(reply, 33, 98));
    Assertions.assertEquals(
      0x6985,
      transmit(IdentityCallerApplet.DECRYPT_DATA, payload(sourcePublicKey, CONTEXT, reply)).getSW()
    );
    acquire(IDENTITY_AID);
    Assertions.assertArrayEquals(
      KEY,
      success(transmit(IdentityCallerApplet.DECRYPT_DATA, payload(targetPublicKey, CONTEXT, reply)))
    );
  }

  @Test
  public void completedDataCannotBeForwardedToAnotherCaller() {
    initializeManager();
    acquire(IDENTITY_AID);
    initializeSecretPIN();
    select(MONOID_CALLER_AID);
    acquire(IDENTITY_AID);
    checkSecretPIN(PIN, true);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    success(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));
    select(UNRELATED_AID);
    success(transmit(IdentityCallerApplet.BORROW_RESULT, AppletTest.aidBytes(MONOID_CALLER_AID)));
    assertDenied(transmit(IdentityCallerApplet.READ_RESULT));
  }

  @Test
  public void reentrantBundleChangesAreRejectedWithoutBlockingLaterCommunication() {
    initializeManager();
    acquire(IDENTITY_AID);
    initializeSecretPIN();
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    Assertions.assertEquals(
      0x6985,
      transmit(IdentityCallerApplet.ENCRYPT_REENTRANT, payload(publicKey, CONTEXT, KEY)).getSW()
    );
    byte[] encrypted = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY))
    );
    Assertions.assertArrayEquals(
      KEY,
      success(transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encrypted)))
    );
  }

  @Test
  public void reentrantPINChangesPreserveAuthorizationAndRetries() {
    initializeManager();
    acquire(IDENTITY_AID);
    initializeSecretPIN();
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] encrypted = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY))
    );

    for (int[] instructions : new int[][] {
      {
        IdentityCallerApplet.ENCRYPT_CHECK_SECRET_PIN_REENTRANT,
        IdentityCallerApplet.ENCRYPT_UPDATE_SECRET_PIN_REENTRANT,
        IdentityCallerApplet.ENCRYPT_CLEAR_SECRET_AUTH_REENTRANT,
      },
      {
        IdentityCallerApplet.DECRYPT_CHECK_SECRET_PIN_REENTRANT,
        IdentityCallerApplet.DECRYPT_UPDATE_SECRET_PIN_REENTRANT,
        IdentityCallerApplet.DECRYPT_CLEAR_SECRET_AUTH_REENTRANT,
      },
    }) {
      boolean decrypt = instructions[0] == IdentityCallerApplet.DECRYPT_CHECK_SECRET_PIN_REENTRANT;

      for (int instruction : instructions) {
        Assertions.assertEquals(
          0x6985,
          transmit(instruction, payload(publicKey, CONTEXT, decrypt ? encrypted : KEY)).getSW()
        );
        assertSecretPINTries(5);
        assertSecretValidation(true);
        Assertions.assertEquals(0, JCSystem.getTransactionDepth());
        byte[] recovered = success(
          transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encrypted))
        );
        Assertions.assertArrayEquals(KEY, recovered);
      }
    }

    checkSecretPIN(PIN, true);
  }

  @Test
  public void identityResetPublishesOnlyAPreparedIdentityWithinTheCallerTransaction() {
    initializeManager();
    acquire(IDENTITY_AID);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] id = success(transmit(IdentityCallerApplet.GET_IDENTITY_ID));
    byte[] token = success(transmit(IdentityCallerApplet.GET_TOKEN));

    Assertions.assertEquals(0x6985, transmit(IdentityCallerApplet.RESET_IDENTITY).getSW());
    Assertions.assertEquals(
      0x6985,
      transmit(IdentityCallerApplet.PREPARE_RESET_IN_TRANSACTION).getSW()
    );
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());

    for (int round = 0; round < 2; round++) {
      initializeSecretPIN();
      byte[] preparedToken = success(transmit(IdentityCallerApplet.PREPARE_RESET));
      Assertions.assertEquals(32, preparedToken.length);
      Assertions.assertFalse(Arrays.equals(token, preparedToken));
      Assertions.assertArrayEquals(
        publicKey,
        success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY))
      );
      Assertions.assertArrayEquals(id, success(transmit(IdentityCallerApplet.GET_IDENTITY_ID)));
      Assertions.assertArrayEquals(token, success(transmit(IdentityCallerApplet.GET_TOKEN)));
      Assertions.assertEquals(
        0x6985,
        transmit(IdentityCallerApplet.RESET_IDENTITY_WITHOUT_TRANSACTION).getSW()
      );

      for (int instruction : new int[] {
        IdentityCallerApplet.ENCRYPT_RESET_REENTRANT,
        IdentityCallerApplet.ENCRYPT_PREPARE_RESET_REENTRANT,
      }) {
        Assertions.assertEquals(
          0x6985,
          transmit(instruction, payload(publicKey, CONTEXT, KEY)).getSW()
        );
        Assertions.assertEquals(0, JCSystem.getTransactionDepth());
        Assertions.assertArrayEquals(
          publicKey,
          success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY))
        );
      }

      // Identity leaves the transaction open for Monoid to commit with its item changes.
      // jCardSim tracks transaction depth but does not emulate persistent-field rollback.
      Assertions.assertArrayEquals(
        new byte[] { 1 },
        success(transmit(IdentityCallerApplet.RESET_IDENTITY))
      );
      Assertions.assertEquals(0, JCSystem.getTransactionDepth());
      Assertions.assertArrayEquals(
        preparedToken,
        success(transmit(IdentityCallerApplet.GET_TOKEN))
      );
      byte[] newPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
      byte[] newId = success(transmit(IdentityCallerApplet.GET_IDENTITY_ID));
      Assertions.assertFalse(Arrays.equals(publicKey, newPublicKey));
      Assertions.assertFalse(Arrays.equals(id, newId));
      assertSecretPINSet(false);
      assertSecretValidation(false);
      assertDenied(
        transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(newPublicKey, CONTEXT, KEY))
      );
      Assertions.assertEquals(0x6985, transmit(IdentityCallerApplet.RESET_IDENTITY).getSW());
      publicKey = newPublicKey;
      id = newId;
      token = preparedToken;
    }
  }

  @Test
  public void identityResetPreparationIsReplacedAndDiscardedByCardReset() {
    initializeManager();
    acquire(IDENTITY_AID);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] token = success(transmit(IdentityCallerApplet.GET_TOKEN));
    byte[] preparedToken = success(transmit(IdentityCallerApplet.PREPARE_RESET));
    byte[] replacementToken = success(transmit(IdentityCallerApplet.PREPARE_RESET));
    Assertions.assertFalse(Arrays.equals(preparedToken, replacementToken));
    success(transmit(IdentityCallerApplet.RESET_IDENTITY));
    Assertions.assertArrayEquals(
      replacementToken,
      success(transmit(IdentityCallerApplet.GET_TOKEN))
    );
    Assertions.assertFalse(
      Arrays.equals(publicKey, success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY)))
    );
    Assertions.assertFalse(Arrays.equals(token, replacementToken));

    publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    success(transmit(IdentityCallerApplet.PREPARE_RESET));
    simulator.reset();
    select(MONOID_AID);
    acquire(IDENTITY_AID);
    Assertions.assertEquals(0x6985, transmit(IdentityCallerApplet.RESET_IDENTITY).getSW());
    Assertions.assertArrayEquals(publicKey, success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY)));
    Assertions.assertArrayEquals(
      replacementToken,
      success(transmit(IdentityCallerApplet.GET_TOKEN))
    );
  }

  @Test
  public void identityResetInvalidatesArtifactsAndEveryCallersToken() {
    initializeManager();
    simulator.installApplet(OTHER_IDENTITY_AID, MonoidIdentityApplet.class);
    select(UNRELATED_AID);
    acquire(IDENTITY_AID);
    byte[] unrelatedToken = success(transmit(IdentityCallerApplet.GET_TOKEN));
    select(MONOID_AID);
    acquire(IDENTITY_AID);
    initializeSecretPIN();
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] encrypted = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY))
    );
    Assertions.assertArrayEquals(
      KEY,
      success(transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encrypted)))
    );

    acquire(OTHER_IDENTITY_AID);
    initializeSecretPIN();
    byte[] senderPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] packet = success(
      transmit(IdentityCallerApplet.CREATE_BUNDLE, concat(senderPublicKey, publicKey))
    );
    byte[] bundle = success(transmit(IdentityCallerApplet.GET_BUNDLE));
    acquire(IDENTITY_AID);
    Assertions.assertArrayEquals(
      bundle,
      success(transmit(IdentityCallerApplet.JOIN_BUNDLE, concat(senderPublicKey, packet)))
    );
    byte[] bundled = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY))
    );
    Assertions.assertEquals(2, bundled[0]);
    byte[] token = success(transmit(IdentityCallerApplet.PREPARE_RESET));
    success(transmit(IdentityCallerApplet.RESET_IDENTITY));
    Assertions.assertArrayEquals(token, success(transmit(IdentityCallerApplet.GET_TOKEN)));
    Assertions.assertEquals(0, success(transmit(IdentityCallerApplet.GET_BUNDLE)).length);
    assertSecretPINSet(false);
    assertSecretValidation(false);
    assertDenied(
      transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encrypted))
    );
    initializeSecretPIN();

    for (byte[] data : new byte[][] { encrypted, bundled }) {
      ResponseAPDU rejected = transmit(
        IdentityCallerApplet.DECRYPT_DATA,
        payload(publicKey, CONTEXT, data)
      );
      Assertions.assertNotEquals(0x9000, rejected.getSW());
      Assertions.assertEquals(0, rejected.getData().length);
    }
    Assertions.assertEquals(
      0x6985,
      transmit(IdentityCallerApplet.JOIN_BUNDLE, concat(senderPublicKey, packet)).getSW()
    );
    Assertions.assertEquals(0, success(transmit(IdentityCallerApplet.GET_BUNDLE)).length);

    byte[] newPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] newEncrypted = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(newPublicKey, CONTEXT, KEY))
    );
    Assertions.assertEquals(1, newEncrypted[0]);
    Assertions.assertArrayEquals(
      KEY,
      success(
        transmit(IdentityCallerApplet.DECRYPT_DATA, payload(newPublicKey, CONTEXT, newEncrypted))
      )
    );
    select(UNRELATED_AID);
    byte[] newUnrelatedToken = success(transmit(IdentityCallerApplet.GET_TOKEN));
    Assertions.assertFalse(Arrays.equals(unrelatedToken, newUnrelatedToken));
    Assertions.assertFalse(Arrays.equals(token, newUnrelatedToken));
    Assertions.assertArrayEquals(
      newUnrelatedToken,
      success(transmit(IdentityCallerApplet.GET_TOKEN))
    );
  }

  @Test
  public void bundleCreationCannotReplaceExistingBundlesAndJoinsAreIdempotent() throws Exception {
    initializeManager();
    simulator.installApplet(OTHER_IDENTITY_AID, MonoidIdentityApplet.class);
    select(MONOID_AID);
    acquire(IDENTITY_AID);
    initializeSecretPIN();
    byte[] senderPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    acquire(OTHER_IDENTITY_AID);
    initializeSecretPIN();
    byte[] recipientPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    acquire(IDENTITY_AID);
    Assertions.assertEquals(0, success(transmit(IdentityCallerApplet.GET_BUNDLE)).length);
    Assertions.assertNotEquals(
      0x9000,
      transmit(IdentityCallerApplet.CREATE_BUNDLE, senderPublicKey).getSW()
    );
    Assertions.assertEquals(0, success(transmit(IdentityCallerApplet.GET_BUNDLE)).length);
    byte[] invalidPublicKey = new byte[65];
    invalidPublicKey[0] = 4;
    Assertions.assertNotEquals(
      0x9000,
      transmit(
        IdentityCallerApplet.CREATE_BUNDLE,
        concat(concat(recipientPublicKey, senderPublicKey), invalidPublicKey)
      ).getSW()
    );
    Assertions.assertEquals(0, success(transmit(IdentityCallerApplet.GET_BUNDLE)).length);
    byte[] envelope = success(
      transmit(IdentityCallerApplet.CREATE_BUNDLE, concat(recipientPublicKey, senderPublicKey))
    );
    byte[] bundle = success(transmit(IdentityCallerApplet.GET_BUNDLE));
    Assertions.assertEquals(32, bundle.length);
    Assertions.assertEquals(
      0x6985,
      transmit(
        IdentityCallerApplet.CREATE_BUNDLE,
        concat(senderPublicKey, recipientPublicKey)
      ).getSW()
    );
    Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));

    acquire(OTHER_IDENTITY_AID);
    Assertions.assertArrayEquals(
      bundle,
      success(transmit(IdentityCallerApplet.JOIN_BUNDLE, concat(senderPublicKey, envelope)))
    );
    Assertions.assertArrayEquals(
      bundle,
      success(transmit(IdentityCallerApplet.JOIN_BUNDLE, concat(senderPublicKey, envelope)))
    );
    Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));

    AID otherSenderAID = AIDUtil.create(
      // @inplate-line "{{hex MONOID_NAMESPACE}}7f14"
      "f06d6f6e6f69647f14"
    );
    simulator.installApplet(otherSenderAID, MonoidIdentityApplet.class);
    select(MONOID_AID);
    acquire(otherSenderAID);
    initializeSecretPIN();
    byte[] otherSenderPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] conflictingEnvelope = success(
      transmit(IdentityCallerApplet.CREATE_BUNDLE, concat(otherSenderPublicKey, recipientPublicKey))
    );
    Assertions.assertFalse(
      Arrays.equals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)))
    );
    acquire(OTHER_IDENTITY_AID);
    Assertions.assertEquals(
      0x6985,
      transmit(
        IdentityCallerApplet.JOIN_BUNDLE,
        concat(otherSenderPublicKey, conflictingEnvelope)
      ).getSW()
    );
    Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));

    Field absenceField = MonoidIdentityApplet.class.getDeclaredField("bundleAbsenceValidation");
    absenceField.setAccessible(true);
    Object recipient = runtime.lookupApplet(OTHER_IDENTITY_AID).getApplet();
    LibSecurity.Condition absence = (LibSecurity.Condition) absenceField.get(recipient);
    final int[] reads = { 0 };
    absenceField.set(recipient, (LibSecurity.Condition) () -> ++reads[0] == 1 || absence.check());
    try {
      // One false "no Bundle" observation must not replace or bypass the existing Bundle.
      Assertions.assertEquals(
        0x6985,
        transmit(
          IdentityCallerApplet.CREATE_BUNDLE,
          concat(senderPublicKey, recipientPublicKey)
        ).getSW()
      );
      Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));
      reads[0] = 0;
      Assertions.assertEquals(
        0x6985,
        transmit(
          IdentityCallerApplet.JOIN_BUNDLE,
          concat(otherSenderPublicKey, conflictingEnvelope)
        ).getSW()
      );
      Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));
      reads[0] = 0;
      Assertions.assertEquals(
        2,
        success(
          transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(recipientPublicKey, CONTEXT, KEY))
        )[0]
      );
      Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));
    } finally {
      absenceField.set(recipient, absence);
    }
    simulator.reset();
    select(MONOID_AID);
    acquire(OTHER_IDENTITY_AID);
    Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));
    assertSecretPINSet(true);
    assertSecretValidation(false);
    assertDenied(transmit(IdentityCallerApplet.JOIN_BUNDLE, concat(senderPublicKey, envelope)));
    checkSecretPIN(PIN, true);

    Assertions.assertArrayEquals(
      recipientPublicKey,
      success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY))
    );
    Assertions.assertArrayEquals(
      bundle,
      success(transmit(IdentityCallerApplet.JOIN_BUNDLE, concat(senderPublicKey, envelope)))
    );
    Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));
  }

  private void initializeManager() {
    runtime = new TokenRuntime();
    simulator = new CardSimulator(runtime);
    simulator.installApplet(IDENTITY_AID, MonoidIdentityApplet.class);
    simulator.installApplet(MONOID_AID, IdentityCallerApplet.class);
    simulator.installApplet(MONOID_CALLER_AID, IdentityCallerApplet.class);
    simulator.installApplet(UNRELATED_AID, IdentityCallerApplet.class);
    select(MONOID_AID);
  }

  private void initializeSecretPIN() {
    success(transmit(IdentityCallerApplet.UPDATE_SECRET_PIN, PIN));
    assertSecretPINSet(true);
    assertSecretValidation(false);
    checkSecretPIN(PIN, true);
  }

  private void checkSecretPIN(byte[] pin, boolean expected) {
    Assertions.assertArrayEquals(
      new byte[] { expected ? (byte) 1 : 0 },
      success(transmit(IdentityCallerApplet.CHECK_SECRET_PIN, pin))
    );
    assertSecretValidation(expected);
  }

  private void assertSecretPINSet(boolean expected) {
    Assertions.assertArrayEquals(
      new byte[] { expected ? (byte) 1 : 0 },
      success(transmit(IdentityCallerApplet.IS_SECRET_PIN_SET))
    );
  }

  private void assertSecretValidation(boolean expected) {
    short value = expected ? Constants.SAFE_TRUE : Constants.SAFE_FALSE;
    Assertions.assertArrayEquals(
      new byte[] { (byte) (value >> 8), (byte) value },
      success(transmit(IdentityCallerApplet.GET_SECRET_PIN_VALIDATION_RESULT))
    );
  }

  private void assertSecretPINTries(int expected) {
    Assertions.assertArrayEquals(
      new byte[] { 0, (byte) expected },
      success(transmit(IdentityCallerApplet.GET_SECRET_PIN_TRIES_REMAINING))
    );
  }

  private byte[] concat(byte[] left, byte[] right) {
    byte[] data = Arrays.copyOf(left, left.length + right.length);
    System.arraycopy(right, 0, data, left.length, right.length);
    return data;
  }

  private byte[] safeId() {
    select(MONOID_AID);
    byte[] request = { (byte) 0xA0 };
    ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(0, 0x20, 0, 0, request));
    CBORBufferReader reader = new CBORBufferReader(success(response));
    reader.map();
    return reader.requireKey("id".getBytes(StandardCharsets.US_ASCII)).bytes().clone();
  }

  private byte[] acquire(AID identityAID) {
    return success(transmit(IdentityCallerApplet.GET_SHAREABLE, AppletTest.aidBytes(identityAID)));
  }

  private void select(AID aid) {
    Assertions.assertTrue(simulator.selectApplet(aid));
  }

  private ResponseAPDU transmit(int instruction) {
    return transmit(instruction, new byte[0]);
  }

  private ResponseAPDU transmit(int instruction, byte[] data) {
    return simulator.transmitCommand(new CommandAPDU(0, instruction, 0, 0, data));
  }

  private byte[] success(ResponseAPDU response) {
    Assertions.assertEquals(0x9000, response.getSW());
    return response.getData();
  }

  private void assertDenied(ResponseAPDU response) {
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED & 0xFFFF, response.getSW());
    Assertions.assertEquals(0, response.getData().length);
  }

  private byte[] payload(byte[] publicKey, byte[] context, byte[] data) {
    byte[] payload = new byte[66 + context.length + data.length];
    System.arraycopy(publicKey, 0, payload, 0, publicKey.length);
    payload[65] = (byte) context.length;
    System.arraycopy(context, 0, payload, 66, context.length);
    System.arraycopy(data, 0, payload, 66 + context.length, data.length);
    return payload;
  }

  private static final class TokenRuntime extends ShareableSimulatorRuntime {

    private int callerReads;

    @Override
    public AID getPreviousContextAID() {
      callerReads++;
      return super.getPreviousContextAID();
    }
  }
}
