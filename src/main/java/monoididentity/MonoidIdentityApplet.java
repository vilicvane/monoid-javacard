package monoididentity;

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
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class MonoidIdentityApplet extends Applet implements IdentityShareable {

  public static final byte ID_LENGTH = 4;

  private byte[] id = new byte[ID_LENGTH];

  private KeyPair keyPair;
  private AESGcmCipher aesGcmCipher;
  private CommunicationCipher communicationCipher;
  private ItemCipher itemCipher;
  private Bundle bundle;
  private final byte[] communicationOperation = JCSystem.makeTransientByteArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );

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
    new MonoidIdentityApplet().register();
  }

  MonoidIdentityApplet() {
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

    byte[] publicKey = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      CommunicationCipher.PUBLIC_KEY_LENGTH
    );
    ((ECPublicKey) keyPair.getPublic()).getW(publicKey, (short) 0);

    return publicKey;
  }

  @Override
  public byte[] getBundle() {
    assertCaller();

    return bundle == null ? null : duplicateAsGlobal(bundle.hash);
  }

  @Override
  public CommunicationDataShareable createBundle(byte[] publicKeys) {
    assertCaller();
    assertCommunicationAvailable();

    byte[] ownPublicKey = publicKey();
    CommunicationCipher cipher = requireCommunicationCipher();
    Bundle replacement = Bundle.create(publicKeys, ownPublicKey, cipher);
    byte[] packets = replacement.encryptPackets(publicKeys, ownPublicKey, cipher);
    CommunicationData result = new CommunicationData(packets, JCSystem.getPreviousContextAID());
    publishBundle(replacement);

    return result;
  }

  @Override
  public byte[] importBundle(byte[] senderPublicKey, byte[] data) {
    assertCaller();
    assertCommunicationAvailable();

    byte[] hash = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      MessageDigest.LENGTH_SHA_256
    );
    Bundle imported = Bundle.decrypt(
      senderPublicKey,
      publicKey(),
      data,
      requireCommunicationCipher()
    );

    if (bundle != null) {
      if (!bundle.matches(imported)) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
    } else {
      publishBundle(imported);
    }

    Util.arrayCopyNonAtomic(bundle.hash, (short) 0, hash, (short) 0, MessageDigest.LENGTH_SHA_256);

    return hash;
  }

  @Override
  public void resetBundle() {
    assertCaller();
    assertCommunicationAvailable();

    publishBundle(null);
  }

  @Override
  public CommunicationDataShareable encryptData(
    byte[] index,
    byte[] key,
    byte[] alias,
    short secret,
    byte[] recipientPublicKey,
    CommunicationDataShareable data
  ) {
    assertCaller();
    assertCommunicationAvailable();
    communicationOperation[0] = 1;

    try {
      byte[] encryptedData = requireItemCipher().encrypt(
        requireCommunicationCipher(),
        bundle,
        index,
        key,
        alias,
        secret,
        recipientPublicKey,
        data
      );

      return new CommunicationData(encryptedData, JCSystem.getPreviousContextAID());
    } finally {
      communicationOperation[0] = 0;
    }
  }

  @Override
  public CommunicationDataShareable decryptData(
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] senderPublicKey,
    CommunicationDataShareable data
  ) {
    assertCaller();
    assertCommunicationAvailable();
    communicationOperation[0] = 1;

    try {
      byte[] plaintext = requireItemCipher().decrypt(
        requireCommunicationCipher(),
        bundle,
        index,
        key,
        alias,
        senderPublicKey,
        data
      );

      return new CommunicationData(plaintext, JCSystem.getPreviousContextAID());
    } finally {
      communicationOperation[0] = 0;
    }
  }

  private void assertCommunicationAvailable() {
    if (communicationOperation[0] != 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private byte[] publicKey() {
    byte[] publicKey = CommunicationData.makePrivateByteArray(
      CommunicationCipher.PUBLIC_KEY_LENGTH
    );
    ((ECPublicKey) keyPair.getPublic()).getW(publicKey, (short) 0);

    return publicKey;
  }

  private void publishBundle(Bundle bundle) {
    JCSystem.beginTransaction();

    try {
      this.bundle = bundle;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }
  }

  private AESGcmCipher requireAESGcmCipher() {
    if (aesGcmCipher == null) {
      // Key envelopes and item data use GCM in sequence, each with a fresh init.
      aesGcmCipher = new AESGcmCipher();
    }

    return aesGcmCipher;
  }

  private ItemCipher requireItemCipher() {
    if (itemCipher == null) {
      itemCipher = new ItemCipher(requireAESGcmCipher());
    }

    return itemCipher;
  }

  private CommunicationCipher requireCommunicationCipher() {
    if (communicationCipher == null) {
      communicationCipher = new CommunicationCipher(keyPair, requireAESGcmCipher());
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
