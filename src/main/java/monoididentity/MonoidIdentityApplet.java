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
  public static final short MAX_ALIAS_LENGTH = 64;

  private static final byte INSTALL_ID = 0x01;
  private static final byte INSTALL_AUTHORITY = 0x02;

  private static final short AUTHORITY_PUBLIC_KEY_LENGTH = 65;

  private static final short TOKEN_LENGTH = 32;
  private static final short TOKEN_CACHE_SIZE = 32;
  private static final short TOKEN_AID_ROUNDS = 3;

  // @formatter:off
  private static final byte[] TOKEN_CONTEXT = {'M','o','n','o','i','d',' ','I','d','e','n','t','i','t','y',' ','T','o','k','e','n'};
  // @formatter:on

  private final byte[] id = new byte[ID_LENGTH];
  private final byte[] alias = new byte[MAX_ALIAS_LENGTH];
  private short aliasLength;

  private final byte[] authority;
  private final ECPublicKey authorityPublicKey;

  private byte[] tokenSecret = new byte[TOKEN_LENGTH];

  private TokenCacheEntry[] tokenCache = new TokenCacheEntry[TOKEN_CACHE_SIZE];
  private short nextTokenCacheIndex;

  private final Object[] preparedReset = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );

  private KeyPair keyPair;

  private SecretPIN secretPIN = new SecretPIN();

  private MessageDigest tokenDigest;
  private byte[] tokenHmacBlock;

  private byte[] hmacBlock;
  private AESGcmCipher aesGcmCipher;

  private CommunicationCipher communicationCipher;
  private BundleExtension bundleExtension;
  private ItemCipher itemCipher;
  private AuthorityTime authorityTime;

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
    short aidOffset = offset;
    byte aidLength = length == 0 ? 0 : buffer[offset];

    if (length != 0) {
      offset += (short) (aidLength + 1);
      offset += (short) ((buffer[offset] & 0xFF) + 1);
      length = buffer[offset++];
    }

    MonoidIdentityApplet applet = new MonoidIdentityApplet(buffer, offset, length);

    if (aidLength == 0) {
      applet.register();
    } else {
      applet.register(buffer, (short) (aidOffset + 1), aidLength);
    }
  }

  MonoidIdentityApplet(byte[] buffer, short offset, byte length) {
    short dataLength = (short) (length & 0xFF);
    byte flags = length == 0 ? 0 : buffer[offset++];

    if ((flags & ~(INSTALL_ID | INSTALL_AUTHORITY)) != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short fixedLength = (short) (1 +
      ((flags & INSTALL_ID) != 0 ? ID_LENGTH : 0) +
      ((flags & INSTALL_AUTHORITY) != 0 ? AUTHORITY_PUBLIC_KEY_LENGTH : 0));

    if (
      (flags & INSTALL_AUTHORITY) != 0
        ? dataLength <= fixedLength
        : dataLength != 0 && dataLength != fixedLength
    ) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    RandomData random = RandomData.getInstance(RandomData.ALG_TRNG);

    if ((flags & INSTALL_ID) != 0) {
      Util.arrayCopyNonAtomic(buffer, offset, id, (short) 0, ID_LENGTH);
      offset += ID_LENGTH;
    } else {
      random.nextBytes(id, (short) 0, ID_LENGTH);
    }

    if ((flags & INSTALL_AUTHORITY) != 0) {
      if (buffer[offset] != 0x04) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      authorityPublicKey = (ECPublicKey) KeyBuilder.buildKey(
        KeyBuilder.ALG_TYPE_EC_FP_PUBLIC,
        JCSystem.MEMORY_TYPE_PERSISTENT,
        KeyBuilder.LENGTH_EC_FP_256,
        false
      );

      LibSECP256r1.initialize(authorityPublicKey);
      authorityPublicKey.setW(buffer, offset, AUTHORITY_PUBLIC_KEY_LENGTH);
      offset += AUTHORITY_PUBLIC_KEY_LENGTH;

      authority = new byte[(short) (dataLength - fixedLength)];
      Util.arrayCopyNonAtomic(buffer, offset, authority, (short) 0, (short) authority.length);
    } else {
      authority = null;
      authorityPublicKey = null;
    }

    random.nextBytes(tokenSecret, (short) 0, TOKEN_LENGTH);

    keyPair = createKeyPair();
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

    byte callerLength = createToken(tokenSecret, caller, token);

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
  public byte[] getAlias() {
    assertCaller();

    if (aliasLength == 0) {
      return null;
    }

    byte[] result = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, aliasLength);
    Util.arrayCopyNonAtomic(alias, (short) 0, result, (short) 0, aliasLength);

    return result;
  }

  @Override
  public void setAlias(byte[] alias) {
    assertMonoidCaller();
    assertCommunicationAvailable();
    assertSecretAuth();

    if (alias.length > MAX_ALIAS_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.beginTransaction();

    try {
      Util.arrayCopy(alias, (short) 0, this.alias, (short) 0, (short) alias.length);
      aliasLength = (short) alias.length;

      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }
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
  public boolean getAllowPeerExtension() {
    assertCaller();

    return bundle != null && bundle.allowPeerExtension;
  }

  @Override
  public byte[] getAuthority() {
    assertCaller();

    return authority == null ? null : duplicateAsGlobal(authority);
  }

  @Override
  public void verifyAuthorityTime(byte[] data, byte[] signature, byte[] challenge) {
    assertCaller();

    if (authorityPublicKey == null) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (authorityTime == null) {
      authorityTime = new AuthorityTime(authorityPublicKey);
    }

    authorityTime.verify(data, signature, challenge);
  }

  @Override
  public boolean isSecretPINSet() {
    assertCaller();

    return secretPIN.isSet();
  }

  @Override
  public short getSecretPINTriesRemaining() {
    assertCaller();

    return secretPIN.getTriesRemaining();
  }

  @Override
  public boolean checkSecretPIN(byte[] pin) {
    assertCaller();
    assertCommunicationAvailable();

    return secretPIN.check(pin);
  }

  @Override
  public void updateSecretPIN(byte[] pin) {
    assertMonoidCaller();
    assertCommunicationAvailable();

    secretPIN.update(pin);
  }

  @Override
  public short getSecretPINValidationResult() {
    assertCaller();

    return secretPIN.getValidationResult();
  }

  @Override
  public void clearSecretAuth() {
    assertCaller();
    assertCommunicationAvailable();

    secretPIN.clearAuth();
  }

  @Override
  public CommunicationDataShareable createBundle(byte[] publicKeys) {
    assertMonoidCaller();
    assertCommunicationAvailable();
    assertSecretAuth();

    if (LibSecurity.check(bundleAbsenceValidation, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] ownPublicKey = publicKey();
    CommunicationCipher cipher = requireCommunicationCipher();

    Bundle created = Bundle.create(publicKeys, ownPublicKey, cipher);

    byte[] packets = created.encryptPackets(publicKeys, cipher);
    CommunicationData result = new CommunicationData(packets, JCSystem.getPreviousContextAID());

    publishBundle(created);

    return result;
  }

  @Override
  public byte[] joinBundle(byte[] senderPublicKey, byte[] data) {
    assertMonoidCaller();
    assertCommunicationAvailable();
    assertSecretAuth();

    byte[] hash = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      MessageDigest.LENGTH_SHA_256
    );

    Bundle joined = Bundle.decrypt(
      senderPublicKey,
      publicKey(),
      data,
      requireCommunicationCipher(),
      authorityPublicKey
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
  public CommunicationDataShareable extendBundle(byte[] publicKey) {
    assertMonoidCaller();
    assertCommunicationAvailable();
    assertSecretAuth();
    assertBundle();

    byte[] request = requireBundleExtension().extend(bundle, publicKey);

    return new CommunicationData(request, JCSystem.getPreviousContextAID());
  }

  @Override
  public CommunicationDataShareable approveBundleExtension(byte[] request) {
    assertMonoidCaller();
    assertCommunicationAvailable();
    assertSecretAuth();
    assertBundle();

    byte[] recipient = requireBundleExtension().requireRecipientPublicKey(bundle, request);

    byte[] data = bundle.encryptFor(recipient, publicKey(), requireCommunicationCipher());

    return new CommunicationData(data, JCSystem.getPreviousContextAID());
  }

  @Override
  public byte[] prepareReset() {
    assertMonoidCaller();
    assertCommunicationAvailable();

    if (JCSystem.getTransactionDepth() != 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    preparedReset[0] = null;
    JCSystem.requestObjectDeletion();

    ResetState state = new ResetState();

    byte[] token = new byte[TOKEN_LENGTH];
    createToken(state.tokenSecret, new byte[16], token);

    byte[] result = duplicateAsGlobal(token);

    preparedReset[0] = state;

    return result;
  }

  @Override
  public void reset() {
    assertMonoidCaller();
    assertCommunicationAvailable();

    if (JCSystem.getTransactionDepth() == 0 || preparedReset[0] == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    ResetState state = (ResetState) preparedReset[0];

    keyPair = state.keyPair;
    secretPIN = state.secretPIN;

    tokenSecret = state.tokenSecret;
    tokenCache = state.tokenCache;
    nextTokenCacheIndex = 0;

    bundle = null;

    communicationCipher = null;
    bundleExtension = null;

    preparedReset[0] = null;

    JCSystem.requestObjectDeletion();
  }

  @Override
  public CommunicationDataShareable encryptData(
    byte[] index,
    byte[] metadata,
    byte[] alias,
    short secret,
    byte[] recipientPublicKey,
    CommunicationDataShareable data
  ) {
    assertCaller();
    assertCommunicationAvailable();
    assertSecretAuth();

    AID caller = JCSystem.getPreviousContextAID();
    communicationOperation[0] = 1;

    try {
      byte[] encryptedData = requireItemCipher().encrypt(
        requireCommunicationCipher(),
        bundle,
        LibSecurity.check(bundleAbsenceValidation, Constants.SAFE_FALSE),
        caller,
        publicKey(),
        index,
        metadata,
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
    byte[] metadata,
    byte[] alias,
    byte[] senderPublicKey,
    CommunicationDataShareable data
  ) {
    assertCaller();
    assertCommunicationAvailable();
    assertSecretAuth();

    AID caller = JCSystem.getPreviousContextAID();
    communicationOperation[0] = 1;

    try {
      byte[] plaintext = requireItemCipher().decrypt(
        requireCommunicationCipher(),
        bundle,
        caller,
        publicKey(),
        index,
        metadata,
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

  private void assertSecretAuth() {
    if (secretPIN.getValidationResult() != Constants.SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  private byte[] publicKey() {
    byte[] publicKey = CommunicationData.makePrivateByteArray(
      CommunicationCipher.PUBLIC_KEY_LENGTH
    );
    ((ECPublicKey) keyPair.getPublic()).getW(publicKey, (short) 0);

    return publicKey;
  }

  private void assertBundle() {
    if (LibSecurity.check(bundleAbsenceValidation, Constants.SAFE_TRUE) != Constants.SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
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
      itemCipher = new ItemCipher(requireAESGcmCipher(), requireHMACBlock());
    }

    return itemCipher;
  }

  private CommunicationCipher requireCommunicationCipher() {
    if (communicationCipher == null) {
      communicationCipher = new CommunicationCipher(
        keyPair,
        requireAESGcmCipher(),
        requireHMACBlock()
      );
    }

    return communicationCipher;
  }

  private byte[] requireHMACBlock() {
    if (hmacBlock == null) {
      // HPKE, item derivation and Bundle requests run in sequence and replace the complete pad.
      hmacBlock = JCSystem.makeTransientByteArray(
        LibHMACSha256.BLOCK_LENGTH,
        JCSystem.CLEAR_ON_RESET
      );
    }

    return hmacBlock;
  }

  private BundleExtension requireBundleExtension() {
    if (bundleExtension == null) {
      bundleExtension = new BundleExtension(keyPair, requireHMACBlock());
    }

    return bundleExtension;
  }

  private static KeyPair createKeyPair() {
    KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);

    LibSECP256r1.initialize((ECPrivateKey) keyPair.getPrivate());
    LibSECP256r1.initialize((ECPublicKey) keyPair.getPublic());

    keyPair.genKeyPair();

    return keyPair;
  }

  private byte createToken(byte[] secret, byte[] caller, byte[] token) {
    if (tokenDigest == null) {
      tokenHmacBlock = new byte[LibHMACSha256.BLOCK_LENGTH];
      tokenDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
    }

    LibHMACSha256.begin(tokenDigest, tokenHmacBlock, secret, (short) 0, TOKEN_LENGTH);
    tokenDigest.update(TOKEN_CONTEXT, (short) 0, (short) TOKEN_CONTEXT.length);

    byte callerLength = 0;

    for (short round = 0; round < TOKEN_AID_ROUNDS; round++) {
      callerLength = JCSystem.getPreviousContextAID().getBytes(caller, (short) 0);
      tokenDigest.update(caller, (short) 0, callerLength);
    }

    tokenDigest.doFinal(caller, (short) 0, (short) 0, token, (short) 0);
    LibHMACSha256.finish(tokenDigest, tokenHmacBlock, token, (short) 0);

    return callerLength;
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

  private static final class ResetState {

    private final byte[] tokenSecret = new byte[TOKEN_LENGTH];
    private final TokenCacheEntry[] tokenCache = new TokenCacheEntry[TOKEN_CACHE_SIZE];

    private final KeyPair keyPair;

    private final SecretPIN secretPIN = new SecretPIN();

    private ResetState() {
      RandomData random = RandomData.getInstance(RandomData.ALG_TRNG);
      random.nextBytes(tokenSecret, (short) 0, TOKEN_LENGTH);

      keyPair = createKeyPair();
    }
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
