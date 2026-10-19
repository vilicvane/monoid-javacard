package monoidsafeidentity;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;

public class MonoidSafeIdentityApplet extends Applet implements SafeIdentityShareable {

  public static final byte ID_LENGTH = 4;

  private byte[] id = new byte[ID_LENGTH];

  private KeyPair keyPair;
  private CommunicationCipher communicationCipher;

  private final Object[] callerCheckParameters = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );

  private final LibSecurity.Condition callerAdmissionValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      AID caller = (AID) callerCheckParameters[0];

      return (
        caller != null &&
        caller.partialEquals(
          Constants.MONOID_AID_WITHOUT_VERSION,
          (short) 0,
          (byte) Constants.MONOID_AID_WITHOUT_VERSION.length
        )
      );
    }
  };

  public static void install(byte[] buffer, short offset, byte length) {
    new MonoidSafeIdentityApplet().register();
  }

  MonoidSafeIdentityApplet() {
    RandomData random = RandomData.getInstance(RandomData.ALG_TRNG);
    random.nextBytes(id, (short) 0, (short) id.length);

    keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    LibSECP256r1.initialize((ECPrivateKey) keyPair.getPrivate());
    LibSECP256r1.initialize((ECPublicKey) keyPair.getPublic());
    keyPair.genKeyPair();
  }

  @Override
  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
  }

  @Override
  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    return checkCaller(clientAID) == Constants.SAFE_TRUE ? this : null;
  }

  @Override
  public byte[] getId() {
    assertCaller();

    return duplicateAsGlobal(id);
  }

  @Override
  public byte[] getPublicKey() {
    assertCaller();

    byte[] publicKey = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) 65);
    ((ECPublicKey) keyPair.getPublic()).getW(publicKey, (short) 0);

    return publicKey;
  }

  @Override
  public byte[] encryptCommunicationKey(byte[] recipientPublicKey, byte[] context, byte[] key) {
    assertCaller();

    return requireCommunicationCipher().encrypt(recipientPublicKey, context, key);
  }

  @Override
  public byte[] decryptCommunicationKey(
    byte[] senderPublicKey,
    byte[] context,
    byte[] encryptedKey
  ) {
    assertCaller();

    return requireCommunicationCipher().decrypt(senderPublicKey, context, encryptedKey);
  }

  private CommunicationCipher requireCommunicationCipher() {
    if (communicationCipher == null) {
      communicationCipher = new CommunicationCipher(keyPair);
    }

    return communicationCipher;
  }

  private void assertCaller() {
    if (checkCaller(JCSystem.getPreviousContextAID()) != Constants.SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  private short checkCaller(AID caller) {
    callerCheckParameters[0] = caller;

    try {
      return LibSecurity.check(callerAdmissionValidation, Constants.SAFE_FALSE);
    } finally {
      callerCheckParameters[0] = null;
    }
  }

  private byte[] duplicateAsGlobal(byte[] data) {
    byte[] duplicate = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      (short) data.length
    );
    Util.arrayCopyNonAtomic(data, (short) 0, duplicate, (short) 0, (short) data.length);

    return duplicate;
  }
}
