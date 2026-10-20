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
  public void repeatedAcquisitionAndResetKeepTheIdentity() {
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
  public void forwardedIdentityUsesTheActualCallerForTokenAndDecryption() {
    acquire(IDENTITY_AID);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] token = success(transmit(IdentityCallerApplet.GET_TOKEN));
    byte[] encrypted = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY))
    );
    select(UNRELATED_AID);
    success(transmit(IdentityCallerApplet.BORROW_IDENTITY, AppletTest.aidBytes(MONOID_CALLER_AID)));

    Assertions.assertArrayEquals(publicKey, success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY)));
    Assertions.assertFalse(Arrays.equals(token, success(transmit(IdentityCallerApplet.GET_TOKEN))));
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
  public void unrelatedAndPrefixCallersCannotManageBundle() {
    AID prefixCaller = AIDUtil.create(concat(AppletTest.aidBytes(MONOID_AID), new byte[] { 1 }));
    simulator.installApplet(prefixCaller, IdentityCallerApplet.class);

    for (AID caller : new AID[] { MONOID_CALLER_AID, UNRELATED_AID, prefixCaller }) {
      select(caller);
      acquire(IDENTITY_AID);
      byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
      assertDenied(transmit(IdentityCallerApplet.CREATE_BUNDLE, publicKey));
      assertDenied(transmit(IdentityCallerApplet.JOIN_BUNDLE, concat(publicKey, new byte[0])));
      assertDenied(transmit(IdentityCallerApplet.RESET_BUNDLE));
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
  public void communicationDataCanBeRecoveredByTheSameIdentityAfterReset() {
    acquire(IDENTITY_AID);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] encryptedKey = success(
      transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY))
    );
    Assertions.assertEquals(KEY.length + 144, encryptedKey.length);

    simulator.reset();
    select(MONOID_CALLER_AID);
    acquire(IDENTITY_AID);
    Assertions.assertArrayEquals(
      KEY,
      success(
        transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, encryptedKey))
      )
    );
  }

  @Test
  public void communicationDataCanBeRecoveredByAnotherIdentity() {
    simulator.installApplet(OTHER_IDENTITY_AID, MonoidIdentityApplet.class);
    select(MONOID_CALLER_AID);
    acquire(IDENTITY_AID);
    byte[] senderPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    acquire(OTHER_IDENTITY_AID);
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
  public void completedDataCannotBeForwardedToAnotherCaller() {
    acquire(IDENTITY_AID);
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
  public void resetBundleRequiresCallerTransactionAndPreservesIdentity() {
    initializeManager();
    simulator.installApplet(OTHER_IDENTITY_AID, MonoidIdentityApplet.class);
    select(MONOID_AID);
    acquire(OTHER_IDENTITY_AID);
    byte[] recipientPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    acquire(IDENTITY_AID);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] id = success(transmit(IdentityCallerApplet.GET_IDENTITY_ID));
    byte[] token = success(transmit(IdentityCallerApplet.GET_TOKEN));
    byte[] members = concat(publicKey, recipientPublicKey);
    success(transmit(IdentityCallerApplet.CREATE_BUNDLE, members));
    byte[] bundle = success(transmit(IdentityCallerApplet.GET_BUNDLE));

    Assertions.assertEquals(
      0x6985,
      transmit(IdentityCallerApplet.RESET_BUNDLE_WITHOUT_TRANSACTION).getSW()
    );
    Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));
    Assertions.assertEquals(
      0x6985,
      transmit(
        IdentityCallerApplet.ENCRYPT_RESET_REENTRANT,
        payload(publicKey, CONTEXT, KEY)
      ).getSW()
    );
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
    Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));
    Assertions.assertEquals(
      2,
      success(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)))[0]
    );

    // Identity leaves the transaction open for Monoid to commit with its item changes.
    // jCardSim tracks transaction depth but does not emulate persistent-field rollback.
    Assertions.assertArrayEquals(
      new byte[] { 1 },
      success(transmit(IdentityCallerApplet.RESET_BUNDLE))
    );
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
    Assertions.assertEquals(0, success(transmit(IdentityCallerApplet.GET_BUNDLE)).length);
    Assertions.assertArrayEquals(publicKey, success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY)));
    Assertions.assertArrayEquals(id, success(transmit(IdentityCallerApplet.GET_IDENTITY_ID)));
    Assertions.assertArrayEquals(token, success(transmit(IdentityCallerApplet.GET_TOKEN)));
    Assertions.assertArrayEquals(
      new byte[] { 1 },
      success(transmit(IdentityCallerApplet.RESET_BUNDLE))
    );
    success(transmit(IdentityCallerApplet.CREATE_BUNDLE, members));
    Assertions.assertFalse(
      Arrays.equals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)))
    );
  }

  @Test
  public void bundleCreationCannotReplaceExistingBundlesAndJoinsAreIdempotent() throws Exception {
    initializeManager();
    simulator.installApplet(OTHER_IDENTITY_AID, MonoidIdentityApplet.class);
    select(MONOID_AID);
    acquire(IDENTITY_AID);
    byte[] senderPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    acquire(OTHER_IDENTITY_AID);
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
    select(MONOID_AID);
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
