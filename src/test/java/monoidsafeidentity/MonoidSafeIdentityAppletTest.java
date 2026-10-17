package monoidsafeidentity;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoidsafe.MonoidSafeApplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tests.AppletTest;
import tests.IdentityCallerApplet;

public class MonoidSafeIdentityAppletTest {

  private static final AID IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_IDENTITY_AID}}"
    "f06d6f6e6f696400010000"
  );
  private static final AID OTHER_IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_IDENTITY_PACKAGE_AID}}010001"
    "f06d6f6e6f696400010001"
  );
  private static final AID SAFE_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_AID}}"
    "f06d6f6e6f696401010000"
  );
  private static final AID SAFE_CALLER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_AID_WITHOUT_VERSION}}0001"
    "f06d6f6e6f696401010001"
  );
  private static final AID MONOID_CALLER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID_WITHOUT_VERSION}}0001"
    "f06d6f6e6f696402010001"
  );

  private static final byte[] CONTEXT = "card transfer".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] KEY = "0123456789ABCDEF0123456789ABCDEF".getBytes(
    StandardCharsets.US_ASCII
  );

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    simulator = new CardSimulator(new ShareableSimulatorRuntime());
    simulator.installApplet(IDENTITY_AID, MonoidSafeIdentityApplet.class);
    simulator.installApplet(SAFE_AID, MonoidSafeApplet.class);
    simulator.installApplet(SAFE_CALLER_AID, IdentityCallerApplet.class);
    simulator.installApplet(MONOID_CALLER_AID, IdentityCallerApplet.class);
    select(SAFE_CALLER_AID);
  }

  @Test
  public void onlySafeCallersCanAcquireIdentity() {
    Assertions.assertArrayEquals(new byte[] { 0 }, acquire(IDENTITY_AID));
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    Assertions.assertEquals(65, publicKey.length);
    Assertions.assertEquals(4, publicKey[0]);
    Assertions.assertEquals(4, success(transmit(IdentityCallerApplet.GET_IDENTITY_ID)).length);

    select(MONOID_CALLER_AID);
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
    select(SAFE_CALLER_AID);
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
  public void forwardedIdentityCannotBeUsedByAMonoidCaller() {
    acquire(IDENTITY_AID);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    select(MONOID_CALLER_AID);
    success(transmit(IdentityCallerApplet.BORROW_IDENTITY, AppletTest.aidBytes(SAFE_CALLER_AID)));

    assertDenied(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    assertDenied(transmit(IdentityCallerApplet.GET_IDENTITY_ID));
    assertDenied(transmit(IdentityCallerApplet.ENCRYPT_KEY, payload(publicKey, CONTEXT, KEY)));
    assertDenied(
      transmit(IdentityCallerApplet.DECRYPT_KEY, payload(publicKey, CONTEXT, new byte[113]))
    );
  }

  @Test
  public void safeIdMatchesIdentityAndSurvivesSafeReplacement() {
    acquire(IDENTITY_AID);
    byte[] id = success(transmit(IdentityCallerApplet.GET_IDENTITY_ID));
    select(MONOID_CALLER_AID);
    Assertions.assertArrayEquals(id, success(transmit(IdentityCallerApplet.GET_SAFE_ID)));

    simulator.deleteApplet(SAFE_AID);
    simulator.createApplet(SAFE_AID, new byte[0], (short) 0, (byte) 0);
    select(MONOID_CALLER_AID);
    Assertions.assertArrayEquals(id, success(transmit(IdentityCallerApplet.GET_SAFE_ID)));

    simulator.reset();
    select(MONOID_CALLER_AID);
    Assertions.assertArrayEquals(id, success(transmit(IdentityCallerApplet.GET_SAFE_ID)));
  }

  @Test
  public void replacingIdentityChangesTheExistingSafeId() {
    acquire(IDENTITY_AID);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    select(MONOID_CALLER_AID);
    byte[] id = success(transmit(IdentityCallerApplet.GET_SAFE_ID));

    simulator.deleteApplet(SAFE_CALLER_AID);
    simulator.deleteApplet(IDENTITY_AID);
    simulator.createApplet(IDENTITY_AID, new byte[0], (short) 0, (byte) 0);
    simulator.createApplet(SAFE_CALLER_AID, new byte[0], (short) 0, (byte) 0);

    select(SAFE_CALLER_AID);
    acquire(IDENTITY_AID);
    Assertions.assertFalse(
      Arrays.equals(publicKey, success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY)))
    );
    byte[] replacementId = success(transmit(IdentityCallerApplet.GET_IDENTITY_ID));
    Assertions.assertFalse(Arrays.equals(id, replacementId));
    select(MONOID_CALLER_AID);
    Assertions.assertArrayEquals(
      replacementId,
      success(transmit(IdentityCallerApplet.GET_SAFE_ID))
    );
  }

  @Test
  public void communicationKeyCanBeRecoveredByTheSameIdentityAfterReset() {
    acquire(IDENTITY_AID);
    byte[] publicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    byte[] encryptedKey = success(
      transmit(IdentityCallerApplet.ENCRYPT_KEY, payload(publicKey, CONTEXT, KEY))
    );
    Assertions.assertEquals(113, encryptedKey.length);

    simulator.reset();
    select(SAFE_CALLER_AID);
    acquire(IDENTITY_AID);
    Assertions.assertArrayEquals(
      KEY,
      success(transmit(IdentityCallerApplet.DECRYPT_KEY, payload(publicKey, CONTEXT, encryptedKey)))
    );
  }

  @Test
  public void communicationKeyCanBeRecoveredByAnotherIdentity() {
    simulator.installApplet(OTHER_IDENTITY_AID, MonoidSafeIdentityApplet.class);
    select(SAFE_CALLER_AID);
    acquire(IDENTITY_AID);
    byte[] senderPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    acquire(OTHER_IDENTITY_AID);
    byte[] recipientPublicKey = success(transmit(IdentityCallerApplet.GET_PUBLIC_KEY));
    acquire(IDENTITY_AID);
    byte[] encryptedKey = success(
      transmit(IdentityCallerApplet.ENCRYPT_KEY, payload(recipientPublicKey, CONTEXT, KEY))
    );

    acquire(OTHER_IDENTITY_AID);
    Assertions.assertArrayEquals(
      KEY,
      success(
        transmit(IdentityCallerApplet.DECRYPT_KEY, payload(senderPublicKey, CONTEXT, encryptedKey))
      )
    );
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
