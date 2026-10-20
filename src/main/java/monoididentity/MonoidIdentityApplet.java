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

  private static final short TOKEN_LENGTH = 32;
  private static final short TOKEN_CACHE_SIZE = 32;
  private static final short TOKEN_AID_ROUNDS = 3;

  // @formatter:off
  private static final byte[] TOKEN_CONTEXT = {'M','o','n','o','i','d',' ','I','d','e','n','t','i','t','y',' ','T','o','k','e','n'};
  // @formatter:on

  private byte[] id = new byte[ID_LENGTH];
  private final byte[] tokenSecret = new byte[TOKEN_LENGTH];
  private final TokenCacheEntry[] tokenCache = new TokenCacheEntry[TOKEN_CACHE_SIZE];
  private short nextTokenCacheIndex;

  private KeyPair keyPair;
  private MessageDigest tokenDigest;
  private byte[] tokenHmacBlock;
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
      return callerCheckParameters[0] != null;
    }
  };

  private final LibSecurity.Condition monoidAdmissionValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      AID caller = (AID) callerCheckParameters[0];

      return (
        caller != null &&
        caller.equals(Constants.MONOID_AID, (short) 0, (byte) Constants.MONOID_AID.length)
      );
    }
  };

  private final LibSecurity.Condition bundleAbsenceValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return bundle == null;
    }
  };

  public static void install(byte[] buffer, short offset, byte length) {
    new MonoidIdentityApplet().register();
  }

  MonoidIdentityApplet() {
    RandomData random = RandomData.getInstance(RandomData.ALG_TRNG);
    random.nextBytes(id, (short) 0, (short) id.length);
    random.nextBytes(tokenSecret, (short) 0, TOKEN_LENGTH);

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
    return checkCaller(clientAID, callerAdmissionValidation) == Constants.SAFE_TRUE ? this : null;
  }

  @Override
  public byte[] getToken() {
    assertCaller();
    assertCommunicationAvailable();

    for (short i = 0; i < TOKEN_CACHE_SIZE; i++) {
      TokenCacheEntry cached = tokenCache[i];

      if (
        cached != null && LibSecurity.check(cached, Constants.SAFE_FALSE) == Constants.SAFE_TRUE
      ) {
        return duplicateAsGlobal(cached.token);
      }
    }

    byte[] token = new byte[TOKEN_LENGTH];
    byte[] caller = new byte[16];
    byte callerLength = 0;

    if (tokenDigest == null) {
      tokenHmacBlock = JCSystem.makeTransientByteArray(
        LibHMACSha256.BLOCK_LENGTH,
        JCSystem.CLEAR_ON_RESET
      );
      tokenDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
    }

    LibHMACSha256.begin(tokenDigest, tokenHmacBlock, tokenSecret, (short) 0, TOKEN_LENGTH);
    tokenDigest.update(TOKEN_CONTEXT, (short) 0, (short) TOKEN_CONTEXT.length);

    for (short round = 0; round < TOKEN_AID_ROUNDS; round++) {
      callerLength = JCSystem.getPreviousContextAID().getBytes(caller, (short) 0);
      tokenDigest.update(caller, (short) 0, callerLength);
    }

    tokenDigest.doFinal(caller, (short) 0, (short) 0, token, (short) 0);
    LibHMACSha256.finish(tokenDigest, tokenHmacBlock, token, (short) 0);

    // A caller's transaction must not make an otherwise valid token request fail.
    if (JCSystem.getTransactionDepth() == 0) {
      TokenCacheEntry entry = new TokenCacheEntry(caller, callerLength, token);
      JCSystem.beginTransaction();

      try {
        tokenCache[nextTokenCacheIndex] = entry;
        nextTokenCacheIndex++;

        if (nextTokenCacheIndex == TOKEN_CACHE_SIZE) {
          nextTokenCacheIndex = 0;
        }

        JCSystem.commitTransaction();
      } finally {
        if (JCSystem.getTransactionDepth() != 0) {
          JCSystem.abortTransaction();
        }
      }
    }

    return duplicateAsGlobal(token);
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
    assertMonoidCaller();
    assertCommunicationAvailable();

    if (LibSecurity.check(bundleAbsenceValidation, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] ownPublicKey = publicKey();
    CommunicationCipher cipher = requireCommunicationCipher();
    Bundle created = Bundle.create(publicKeys, ownPublicKey, cipher);
    byte[] packets = created.encryptPackets(publicKeys, ownPublicKey, cipher);
    CommunicationData result = new CommunicationData(packets, JCSystem.getPreviousContextAID());
    publishBundle(created);

    return result;
  }

  @Override
  public byte[] joinBundle(byte[] senderPublicKey, byte[] data) {
    assertMonoidCaller();
    assertCommunicationAvailable();

    byte[] hash = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      MessageDigest.LENGTH_SHA_256
    );
    Bundle joined = Bundle.decrypt(
      senderPublicKey,
      publicKey(),
      data,
      requireCommunicationCipher()
    );

    if (LibSecurity.check(bundleAbsenceValidation, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
      if (!bundle.matches(joined)) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
    } else {
      publishBundle(joined);
    }

    Util.arrayCopyNonAtomic(bundle.hash, (short) 0, hash, (short) 0, MessageDigest.LENGTH_SHA_256);

    return hash;
  }

  @Override
  public void resetBundle() {
    assertMonoidCaller();
    assertCommunicationAvailable();

    if (JCSystem.getTransactionDepth() == 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    bundle = null;
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
    AID caller = JCSystem.getPreviousContextAID();
    communicationOperation[0] = 1;

    try {
      byte[] encryptedData = requireItemCipher().encrypt(
        requireCommunicationCipher(),
        bundle,
        LibSecurity.check(bundleAbsenceValidation, Constants.SAFE_FALSE),
        caller,
        index,
        key,
        alias,
        secret,
        recipientPublicKey,
        data
      );

      return new CommunicationData(encryptedData, caller);
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
    AID caller = JCSystem.getPreviousContextAID();
    communicationOperation[0] = 1;

    try {
      byte[] plaintext = requireItemCipher().decrypt(
        requireCommunicationCipher(),
        bundle,
        caller,
        index,
        key,
        alias,
        senderPublicKey,
        data
      );

      return new CommunicationData(plaintext, caller);
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
    if (
      checkCaller(JCSystem.getPreviousContextAID(), callerAdmissionValidation) !=
      Constants.SAFE_TRUE
    ) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  private void assertMonoidCaller() {
    if (
      checkCaller(JCSystem.getPreviousContextAID(), monoidAdmissionValidation) !=
      Constants.SAFE_TRUE
    ) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  private short checkCaller(AID caller, LibSecurity.Condition validation) {
    callerCheckParameters[0] = caller;

    try {
      return LibSecurity.check(validation, Constants.SAFE_FALSE);
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

  private static final class TokenCacheEntry implements LibSecurity.Condition {

    private final byte[] caller;
    private final byte callerLength;
    private final byte[] token;

    private TokenCacheEntry(byte[] caller, byte callerLength, byte[] token) {
      this.caller = caller;
      this.callerLength = callerLength;
      this.token = token;
    }

    @Override
    public boolean check() {
      return JCSystem.getPreviousContextAID().equals(caller, (short) 0, callerLength);
    }
  }
}
