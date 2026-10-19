package monoididentity;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.ISO7816;
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
    "f06d6f6e6f696400010000"
  );
  private static final AID OTHER_IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_IDENTITY_PACKAGE_AID}}010001"
    "f06d6f6e6f696400010001"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f696402010000"
  );
  private static final AID MONOID_CALLER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID_WITHOUT_VERSION}}0001"
    "f06d6f6e6f696402010001"
  );
  private static final AID UNRELATED_AID = AIDUtil.create("f06d6f6e6f696401010001");

  private static final byte[] CONTEXT = "card transfer".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] KEY = "0123456789ABCDEF0123456789ABCDEF".getBytes(
    StandardCharsets.US_ASCII
  );

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    simulator = new CardSimulator(new ShareableSimulatorRuntime());
    simulator.installApplet(IDENTITY_AID, MonoidIdentityApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    simulator.installApplet(MONOID_CALLER_AID, IdentityCallerApplet.class);
    simulator.installApplet(UNRELATED_AID, IdentityCallerApplet.class);
    select(MONOID_CALLER_AID);
  }

  @Test
  public void onlyMonoidCallersCanAcquireIdentity() {
    Assertions.assertArrayEquals(new byte[] { 0 }, acquire(IDENTITY_AID));
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    Assertions.assertEquals(65, publicKey.length);
    Assertions.assertEquals(4, publicKey[0]);
    Assertions.assertEquals(4, success(transmit(IdentityCallerApplet.GET_IDENTITY_ID)).length);

    select(UNRELATED_AID);
    assertDenied(transmit(IdentityCallerApplet.GET_SHAREABLE, AppletTest.aidBytes(IDENTITY_AID)));
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
  public void forwardedIdentityCannotBeUsedByAnOldSafeCaller() {
    acquire(IDENTITY_AID);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    select(UNRELATED_AID);
    success(transmit(IdentityCallerApplet.BORROW_IDENTITY, AppletTest.aidBytes(MONOID_CALLER_AID)));

    assertDenied(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    assertDenied(transmit(IdentityCallerApplet.GET_IDENTITY_ID));
    assertDenied(transmit(IdentityCallerApplet.ENCRYPT_DATA, payload(publicKey, CONTEXT, KEY)));
    assertDenied(
      transmit(IdentityCallerApplet.DECRYPT_DATA, payload(publicKey, CONTEXT, new byte[113]))
    );
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
  public void replacingIdentityChangesTheExistingSafeId() {
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
  public void bundleReplacementIsAtomicAndImportsAreIdempotentUntilExplicitlyRemoved() {
    simulator.installApplet(OTHER_IDENTITY_AID, MonoidIdentityApplet.class);
    select(MONOID_CALLER_AID);
    acquire(IDENTITY_AID);
    byte[] senderPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    acquire(OTHER_IDENTITY_AID);
    byte[] recipientPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    acquire(IDENTITY_AID);
    Assertions.assertEquals(0, success(transmit(IdentityCallerApplet.GET_BUNDLE)).length);
    success(
      transmit(IdentityCallerApplet.CREATE_BUNDLE, concat(recipientPublicKey, senderPublicKey))
    );
    byte[] originalBundle = success(transmit(IdentityCallerApplet.GET_BUNDLE));
    Assertions.assertNotEquals(
      0x9000,
      transmit(IdentityCallerApplet.CREATE_BUNDLE, senderPublicKey).getSW()
    );
    Assertions.assertArrayEquals(
      originalBundle,
      success(transmit(IdentityCallerApplet.GET_BUNDLE))
    );
    byte[] invalidPublicKey = new byte[65];
    invalidPublicKey[0] = 4;
    Assertions.assertNotEquals(
      0x9000,
      transmit(
        IdentityCallerApplet.CREATE_BUNDLE,
        concat(concat(recipientPublicKey, senderPublicKey), invalidPublicKey)
      ).getSW()
    );
    Assertions.assertArrayEquals(
      originalBundle,
      success(transmit(IdentityCallerApplet.GET_BUNDLE))
    );
    byte[] envelope = success(
      transmit(IdentityCallerApplet.CREATE_BUNDLE, concat(senderPublicKey, recipientPublicKey))
    );
    byte[] bundle = success(transmit(IdentityCallerApplet.GET_BUNDLE));
    Assertions.assertEquals(32, bundle.length);
    Assertions.assertFalse(Arrays.equals(originalBundle, bundle));

    acquire(OTHER_IDENTITY_AID);
    Assertions.assertArrayEquals(
      bundle,
      success(transmit(IdentityCallerApplet.IMPORT_BUNDLE, concat(senderPublicKey, envelope)))
    );
    Assertions.assertArrayEquals(
      bundle,
      success(transmit(IdentityCallerApplet.IMPORT_BUNDLE, concat(senderPublicKey, envelope)))
    );
    Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));
    simulator.reset();
    select(MONOID_CALLER_AID);
    acquire(OTHER_IDENTITY_AID);
    Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));

    success(transmit(IdentityCallerApplet.RESET_BUNDLE));
    Assertions.assertEquals(0, success(transmit(IdentityCallerApplet.GET_BUNDLE)).length);
    Assertions.assertArrayEquals(
      recipientPublicKey,
      success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY))
    );
    Assertions.assertArrayEquals(
      bundle,
      success(transmit(IdentityCallerApplet.IMPORT_BUNDLE, concat(senderPublicKey, envelope)))
    );
    Assertions.assertArrayEquals(bundle, success(transmit(IdentityCallerApplet.GET_BUNDLE)));
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
}
