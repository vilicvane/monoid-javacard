package monoid;

import static monoid.Constants.SAFE_FALSE;
import static monoid.Constants.SAFE_TRUE;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import monoididentity.CommunicationDataShareable;
import monoididentity.IdentityShareable;
import monoididentity.MonoidIdentityApplet;
import monoidlib.CBORReader;
import monoidlib.LibSecurity;
import monoidlib.Utils;

public final class Safe {

  public static final byte INDEX_TYPE_OFFSET = 0;
  public static final byte INDEX_TYPE_LENGTH = 2;
  public static final byte INDEX_TYPE_CATEGORY_OFFSET = 0;
  public static final byte INDEX_TYPE_METADATA_OFFSET = INDEX_TYPE_CATEGORY_OFFSET + 1;

  public static final byte INDEX_ID_OFFSET = INDEX_TYPE_OFFSET + INDEX_TYPE_LENGTH;
  public static final byte INDEX_ID_LENGTH = 8;

  public static final byte INDEX_LENGTH = INDEX_TYPE_LENGTH + INDEX_ID_LENGTH;

  public static final short TYPE_MASK = (short) 0xFFFF;
  public static final short TYPE_CATEGORY_MASK = (short) 0xFF00;
  public static final short TYPE_METADATA_MASK = 0x00FF;
  public static final short TYPE_RESERVED_END = 0x1000;

  public static final short TYPE_ENTROPY = 0x0100;
  public static final short TYPE_SEED = 0x0200;
  public static final short TYPE_WEIERSTRASS = 0x0300;
  public static final short TYPE_WEIERSTRASS_SECP256K1 = TYPE_WEIERSTRASS | 0x01;
  public static final short TYPE_WEIERSTRASS_SECP256R1 = TYPE_WEIERSTRASS | 0x02;
  public static final short TYPE_EDWARDS = 0x0400;
  public static final short TYPE_EDWARDS_ED25519 = TYPE_EDWARDS | 0x01;
  public static final short TYPE_HMAC = 0x0500;
  public static final short TYPE_GENERIC = 0x0FFF;
  public static final short TYPE_RESERVED_EXTENSION_MARK = (short) 0xFFFF;

  // Pairs of exact custom item type and built-in key kind.
  private static final short[] MAPPED_KEY_TYPES = { (short) 0xF201, TYPE_HMAC };

  // @formatter:off
  public static final byte[] TYPE_TEXT_ENTROPY = {'e','n','t','r','o','p','y'};
  public static final byte[] TYPE_TEXT_SEED = {'s','e','e','d'};
  public static final byte[] TYPE_TEXT_SECP256K1 = {'s','e','c','p','2','5','6','k','1'};
  public static final byte[] TYPE_TEXT_SECP256R1 = {'s','e','c','p','2','5','6','r','1'};
  public static final byte[] TYPE_TEXT_ED25519 = {'e','d','2','5','5','1','9'};
  public static final byte[] TYPE_TEXT_HMAC = {'h','m','a','c'};
  // @formatter:on

  private static final short AUTH_ACCESS = (short) 0x5AFE;

  private static final short ITEM_LENGTH_EXTENSION = 8;
  private static final short MIN_AVAILABLE_PERSISTENT_MEMORY = 4096;

  private final short[] auth = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);

  private final Object[] session = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );

  private final LibSecurity.Condition authorizationValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      if (auth[0] == 0 && auth[1] == 0) {
        return false;
      }

      if (auth[0] != AUTH_ACCESS || auth[1] != (short) ~AUTH_ACCESS) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      return true;
    }
  };

  private SafeItem[] items = new SafeItem[ITEM_LENGTH_EXTENSION];

  private final AppletGrants appletGrants = new AppletGrants(this);

  private short itemsLength = 0;

  private Object itemsRevision = new Object();

  private final short[] availableMemory = JCSystem.makeTransientShortArray(
    (short) 2,
    JCSystem.CLEAR_ON_RESET
  );

  private MessageDigest indexDigest;
  private ItemCipher itemCipher;
  private byte[] identityToken;

  void initializeIdentity() {
    if (identityToken == null) {
      identityToken = Utils.duplicateAsPersistent(getIdentity().getToken());
    }
  }

  public byte[] getId() {
    return requireIdentity().getId();
  }

  public byte[] getPublicKey() {
    return requireIdentity().getPublicKey();
  }

  public byte[] getAlias() {
    return requireIdentity().getAlias();
  }

  public void setAlias(byte[] alias) {
    Command.requireAuth(Command.AUTH_SECRET);
    checkAccess();

    if (alias.length > MonoidIdentityApplet.MAX_ALIAS_LENGTH) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    }

    requireIdentity().setAlias(Utils.duplicateAsGlobal(alias));
  }

  public byte[] getAuthority() {
    return requireIdentity().getAuthority();
  }

  public byte[] getBundle() {
    return requireIdentity().getBundle();
  }

  public boolean getAllowPeerExtension() {
    return requireIdentity().getAllowPeerExtension();
  }

  public SafeDataSource createBundle(byte[] publicKeys) {
    Command.requireAuth(Command.AUTH_SECRET);
    checkAccess();

    return new SafeIdentityData(
      this,
      requireIdentity().createBundle(Utils.duplicateAsGlobal(publicKeys))
    );
  }

  /** Both inputs must be global arrays for the Identity call. */
  public byte[] joinBundle(byte[] senderPublicKey, byte[] data) {
    Command.requireAuth(Command.AUTH_SECRET);
    checkAccess();

    return requireIdentity().joinBundle(senderPublicKey, data);
  }

  /** The input must be a global array for the Identity call. */
  public SafeDataSource extendBundle(byte[] publicKey) {
    Command.requireAuth(Command.AUTH_SECRET);
    checkAccess();

    return new SafeIdentityData(this, requireIdentity().extendBundle(publicKey));
  }

  /** The input must be a global array for the Identity call. */
  public SafeDataSource approveBundleExtension(byte[] request) {
    Command.requireAuth(Command.AUTH_SECRET);
    checkAccess();

    return new SafeIdentityData(this, requireIdentity().approveBundleExtension(request));
  }

  public void reset() {
    IdentityShareable identity = requireIdentity();
    SafeItem[] emptyItems = new SafeItem[ITEM_LENGTH_EXTENSION];
    OwnerPIN accessPIN = new OwnerPIN(MonoidApplet.PIN_TRY_LIMIT, MonoidApplet.MAX_PIN_LENGTH);
    byte[] token = Utils.duplicateAsPersistent(identity.prepareReset());
    JCSystem.beginTransaction();

    try {
      items = emptyItems;
      itemsLength = 0;
      appletGrants.clear();
      MonoidApplet.resetPIN(accessPIN);
      KeyDerivation.clearCache();
      identity.reset();
      identityToken = token;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }

    clearAuth();
    Command.clearAuth();
    JCSystem.requestObjectDeletion();
  }

  private IdentityShareable requireIdentity() {
    IdentityShareable identity = getIdentity();
    byte[] token = identity.getToken();

    if (LibSecurity.check(identityToken, token, SAFE_FALSE) != SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    return identity;
  }

  private IdentityShareable getIdentity() {
    AID identityAID = JCSystem.lookupAID(
      Constants.MONOID_IDENTITY_AID,
      (short) 0,
      (byte) Constants.MONOID_IDENTITY_AID.length
    );
    IdentityShareable identity = identityAID == null
      ? null
      : (IdentityShareable) JCSystem.getAppletShareableInterfaceObject(identityAID, (byte) 0);

    if (identity == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    return identity;
  }

  private ItemCipher requireItemCipher() {
    if (itemCipher == null) {
      itemCipher = new ItemCipher(this);
    }

    return itemCipher;
  }

  public boolean isPINSet() {
    return requireIdentity().isSecretPINSet();
  }

  short getPINSetResult(short conservativeResult) {
    final IdentityShareable identity = requireIdentity();
    LibSecurity.Condition condition = new LibSecurity.Condition() {
      @Override
      public boolean check() {
        return identity.isSecretPINSet();
      }
    };

    return LibSecurity.check(condition, conservativeResult);
  }

  short getPINBlockedResult() {
    final IdentityShareable identity = requireIdentity();
    LibSecurity.Condition condition = new LibSecurity.Condition() {
      @Override
      public boolean check() {
        return identity.getSecretPINTriesRemaining() == 0;
      }
    };

    return LibSecurity.check(condition, SAFE_TRUE);
  }

  public short getPINTriesRemaining() {
    return requireIdentity().getSecretPINTriesRemaining();
  }

  public boolean checkPIN(byte[] pin) {
    clearAuth();
    return requireIdentity().checkSecretPIN(Utils.duplicateAsGlobal(pin));
  }

  public void updatePIN(byte[] pin) {
    clearAuth();
    requireIdentity().updateSecretPIN(Utils.duplicateAsGlobal(pin));
  }

  public boolean isPINValidated() {
    return getPINValidationResult() == SAFE_TRUE;
  }

  short getPINValidationResult() {
    return requireIdentity().getSecretPINValidationResult();
  }

  public SafeItemIterator list(short type) {
    return list(type, null);
  }

  AppletGrants getAppletGrants() {
    return appletGrants;
  }

  public SafeItemIterator list(short type, byte[] metadataPrefix) {
    assertAccess();
    return new SafeItemIterator(this, items, itemsLength, type, metadataPrefix);
  }

  SafeItemIterator list(short type, byte[] metadataPrefix, AppletGrant grant) {
    assertAccess();
    return new SafeItemIterator(this, items, itemsLength, type, metadataPrefix, grant);
  }

  Object getItemsRevision() {
    return itemsRevision;
  }

  short listIndices(
    short type,
    byte[] metadataPrefix,
    short metadataOffset,
    short metadataLength,
    byte[] dest,
    short offset,
    short capacity,
    AppletGrant grant
  ) {
    assertAccess();
    short count = 0;
    for (short index = 0; index < itemsLength; index++) {
      SafeItem item = items[index];
      if (
        item.matches(type) &&
        grant.allows(Util.getShort(item.index, INDEX_TYPE_OFFSET), false) &&
        (metadataLength == 0 ||
          (item.metadata != null &&
            metadataLength <= item.metadata.length &&
            Util.arrayCompare(
              item.metadata,
              (short) 0,
              metadataPrefix,
              metadataOffset,
              metadataLength
            ) ==
            0))
      ) {
        if (count < capacity) {
          Util.arrayCopyNonAtomic(item.index, (short) 0, dest, offset, INDEX_LENGTH);
          offset += INDEX_LENGTH;
        }
        count++;
      }
    }
    return count;
  }

  public SafeItem get(byte[] index) {
    assertAccess();
    return getItem(index);
  }

  SafeItem get(byte[] index, short offset) {
    assertAccess();

    for (short itemIndex = 0; itemIndex < itemsLength; itemIndex++) {
      SafeItem item = items[itemIndex];

      if (Util.arrayCompare(item.index, (short) 0, index, offset, INDEX_LENGTH) == 0) {
        return item;
      }
    }

    return null;
  }

  private SafeItem getItem(byte[] index) {
    for (short itemIndex = 0; itemIndex < itemsLength; itemIndex++) {
      SafeItem item = items[itemIndex];

      if (item.matches(index)) {
        return item;
      }
    }

    return null;
  }

  public SafeItem createKnownRandom(short type) throws SafeException {
    switch (type) {
      case TYPE_WEIERSTRASS_SECP256K1:
        return createRandomRandom(type, (short) CurveSECP256k1.KEY_LENGTH);
      case TYPE_WEIERSTRASS_SECP256R1:
        return createRandomScalar(type, CurveSECP256r1.R);
      case TYPE_EDWARDS_ED25519:
        return createRandomRandom(type, (short) CurveED25519.KEY_LENGTH);
    }

    switch (type & TYPE_CATEGORY_MASK) {
      case TYPE_ENTROPY:
      case TYPE_SEED:
      case TYPE_HMAC: {
        short keyLength = (short) (type & TYPE_METADATA_MASK);

        if (keyLength == 0) {
          SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        }

        return createRandomRandom(type, keyLength);
      }
    }

    SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
    return null;
  }

  /**
   * By "random random", I mean a random with (practically) all possibilities
   * being valid.
   *
   * A uniformly random 32-byte value is a valid SECP256K1 scalar with
   * overwhelming probability. Ed25519 stores a 32-byte seed, for which every
   * bit pattern is valid; expansion and clamping happen when importing it.
   */
  private SafeItem createRandomRandom(short refinedType, short length) {
    byte[] data = new byte[length];

    OneShot.random(data, (short) 0, length);

    SafeData source = new SafeData(data);
    byte[] index = buildDigestIndex(refinedType, source);

    return createItem(index, null, null, source, SAFE_TRUE);
  }

  private SafeItem createRandomScalar(short refinedType, byte[] order) {
    byte[] data = new byte[order.length];

    do {
      OneShot.random(data, (short) 0, (short) data.length);
    } while (!isValidScalar(data, order));

    SafeData source = new SafeData(data);
    byte[] index = buildDigestIndex(refinedType, source);

    return createItem(index, null, null, source, SAFE_TRUE);
  }

  public SafeItem require(byte[] index) {
    SafeItem item = get(index);

    if (item == null) {
      SafeException.throwIt(SafeException.REASON_NOT_FOUND);
    }

    return item;
  }

  public SafeItem create(
    short type,
    byte[] metadata,
    byte[] alias,
    SafeDataSource data,
    boolean secret
  ) throws SafeException {
    if (!isKnownDigestIndexedType(type)) {
      SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
    }

    type = refineType(type, data);

    byte[] index = buildDigestIndex(type, data);

    return createItem(index, metadata, alias, data, secret ? SAFE_TRUE : SAFE_FALSE);
  }

  public SafeItem create(
    byte[] index,
    byte[] metadata,
    byte[] alias,
    SafeDataSource data,
    boolean secret
  ) {
    if (index.length != Safe.INDEX_LENGTH) {
      SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
    }

    byte[] builtIndex = validateIndex(index, data);
    return createItem(builtIndex, metadata, alias, data, secret ? SAFE_TRUE : SAFE_FALSE);
  }

  byte[] validateIndex(byte[] index, SafeDataSource data) {
    short type = Util.getShort(index, Safe.INDEX_TYPE_OFFSET);

    byte[] builtIndex;

    if (isKnownDigestIndexedType(type)) {
      if (type != refineType(type, data)) {
        SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
      }

      builtIndex = buildDigestIndex(type, data);

      // Validate digest.
      if (
        Util.arrayCompare(
          index,
          Safe.INDEX_ID_OFFSET,
          builtIndex,
          Safe.INDEX_ID_OFFSET,
          Safe.INDEX_ID_LENGTH
        ) !=
        0
      ) {
        SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
      }
    } else {
      builtIndex = index;
    }

    return builtIndex;
  }

  boolean createData(
    byte[] index,
    short indexOffset,
    byte[] metadata,
    short metadataOffset,
    short metadataLength,
    byte[] alias,
    byte[] data,
    short dataOffset,
    short dataLength,
    boolean secret
  ) {
    if (get(index, indexOffset) != null) {
      return false;
    }

    checkStorage(
      (short) (INDEX_LENGTH +
        metadataLength +
        (alias == null ? 0 : alias.length) +
        getItemTableExtensionLength())
    );
    byte[] ownedIndex = Utils.duplicateAsPersistent(index, indexOffset, INDEX_LENGTH);
    byte[] ownedMetadata = metadata == null
      ? null
      : Utils.duplicateAsPersistent(metadata, metadataOffset, metadataLength);
    byte[] ownedAlias = alias == null ? null : Utils.duplicateAsPersistent(alias);
    checkStorage((short) (dataLength + getItemTableExtensionLength()));
    byte[] storedData = Utils.duplicateAsPersistent(data, dataOffset, dataLength);

    if (isKnownDigestIndexedType(Util.getShort(ownedIndex, INDEX_TYPE_OFFSET))) {
      // Only owned bytes enter an object field; the caller's global array is never retained.
      validateIndex(ownedIndex, new SafeData(storedData));
    }

    assertAccess();
    return (
      finishCreate(
        ownedIndex,
        ownedMetadata,
        ownedAlias,
        storedData,
        secret ? SAFE_TRUE : SAFE_FALSE
      ) !=
      null
    );
  }

  private SafeItem createItem(
    byte[] index,
    byte[] metadata,
    byte[] alias,
    SafeDataSource data,
    short secret
  ) {
    assertAccess();

    if (getItem(index) != null) {
      return null;
    }

    checkStorage(getItemStorageLength(index, metadata, alias, (short) 0));
    index = Utils.duplicateAsPersistent(index);
    metadata = metadata != null ? Utils.duplicateAsPersistent(metadata) : null;
    alias = alias != null ? Utils.duplicateAsPersistent(alias) : null;

    short dataLength = data.getLength();
    assertAccess();
    checkStorage((short) (dataLength + getItemTableExtensionLength()));
    byte[] storedData = data.duplicateAsPersistent(dataLength);
    assertAccess();

    return finishCreate(index, metadata, alias, storedData, secret);
  }

  private SafeItem finishCreate(
    byte[] index,
    byte[] metadata,
    byte[] alias,
    byte[] storedData,
    short secret
  ) {
    if (getItem(index) != null) {
      return null;
    }

    short extensionLength = getItemTableExtensionLength();

    if (extensionLength > 0) {
      checkStorage(extensionLength);
    }

    return publishItem(index, metadata, alias, storedData, secret);
  }

  private short getItemStorageLength(
    byte[] index,
    byte[] metadata,
    byte[] alias,
    short dataLength
  ) {
    short length = (short) (index.length + dataLength);

    if (metadata != null) {
      length += (short) metadata.length;
    }

    if (alias != null) {
      length += (short) alias.length;
    }

    return (short) (length + getItemTableExtensionLength());
  }

  private short getItemTableExtensionLength() {
    // Estimate the new reference array; object headers are covered by the reserve.
    return itemsLength == items.length
      ? (short) ((short) (items.length + ITEM_LENGTH_EXTENSION) * 2)
      : 0;
  }

  private SafeItem publishItem(
    byte[] index,
    byte[] metadata,
    byte[] alias,
    byte[] data,
    short secret
  ) {
    SafeItem item = new SafeItem(this, index, metadata, alias, data, secret);
    SafeItem[] updatedItems = items;

    if (itemsLength == items.length) {
      updatedItems = new SafeItem[(short) (items.length + ITEM_LENGTH_EXTENSION)];

      for (short itemIndex = 0; itemIndex < itemsLength; itemIndex++) {
        updatedItems[itemIndex] = items[itemIndex];
      }
    }

    boolean extended = updatedItems != items;
    Object revision = new Object();
    boolean transaction = JCSystem.getTransactionDepth() == 0;

    if (transaction) {
      JCSystem.beginTransaction();
    }

    try {
      items = updatedItems;
      items[itemsLength++] = item;
      itemsRevision = revision;
      if (transaction) {
        JCSystem.commitTransaction();
      }
    } finally {
      if (transaction && JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }

    if (extended) {
      JCSystem.requestObjectDeletion();
    }

    return item;
  }

  public SafeDataSource exportItem(SafeItem item, byte[] recipientPublicKey) {
    assertAccess();
    SafeDataSource data = requireItemCipher().encrypt(requireIdentity(), item, recipientPublicKey);
    assertAccess();
    return data;
  }

  public void importItem(
    byte[] index,
    byte[] metadata,
    byte[] alias,
    byte[] senderPublicKey,
    SafeDataSource data
  ) {
    assertAccess();

    // Reserve the cross-applet read buffer.
    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) 64);

    index = Utils.duplicateAsPersistent(index);
    metadata = metadata != null ? Utils.duplicateAsPersistent(metadata) : null;
    alias = alias != null ? Utils.duplicateAsPersistent(alias) : null;
    senderPublicKey = senderPublicKey != null ? Utils.duplicateAsPersistent(senderPublicKey) : null;

    CommunicationDataShareable plaintext = requireItemCipher().decrypt(
      requireIdentity(),
      index,
      metadata,
      alias,
      senderPublicKey,
      data
    );
    assertAccess();
    plaintext.read((short) 0, buffer, (short) 0, ItemCipher.SECRET_LENGTH);
    short secret = Util.getShort(buffer, (short) 0);

    if (secret != SAFE_TRUE && secret != SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    short dataLength = (short) (plaintext.getLength() - ItemCipher.SECRET_LENGTH);

    if (getItem(index) != null) {
      SafeException.throwIt(SafeException.REASON_EXISTS);
    }

    checkStorage(getItemStorageLength(index, metadata, alias, dataLength));
    index = Utils.duplicateAsPersistent(index);
    metadata = metadata != null ? Utils.duplicateAsPersistent(metadata) : null;
    alias = alias != null ? Utils.duplicateAsPersistent(alias) : null;
    byte[] storedData = new byte[dataLength];

    for (short offset = 0; offset < dataLength; ) {
      short length = Utils.min((short) (dataLength - offset), (short) buffer.length);
      plaintext.read((short) (ItemCipher.SECRET_LENGTH + offset), buffer, (short) 0, length);
      Util.arrayCopyNonAtomic(buffer, (short) 0, storedData, offset, length);
      offset += length;
    }

    assertAccess();

    if (getMappedKeyType(Util.getShort(index, INDEX_TYPE_OFFSET)) != 0) {
      validateIndex(index, new SafeData(storedData));
    }

    publishItem(index, metadata, alias, storedData, secret);
  }

  public void remove(SafeItem item) {
    assertAccess();

    short indexToDelete = -1;

    for (short index = 0; index < itemsLength; index++) {
      if (items[index] == item) {
        indexToDelete = index;
        break;
      }
    }

    if (indexToDelete < 0) {
      return;
    }

    Object revision = new Object();
    boolean transaction = JCSystem.getTransactionDepth() == 0;

    if (transaction) {
      JCSystem.beginTransaction();
    }

    try {
      for (short index = indexToDelete; index < (short) (itemsLength - 1); index++) {
        items[index] = items[(short) (index + 1)];
      }

      items[--itemsLength] = null;
      itemsRevision = revision;

      if (transaction) {
        JCSystem.commitTransaction();
      }
    } finally {
      if (transaction && JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }

    JCSystem.requestObjectDeletion();
  }

  void removeAll(short type) {
    assertAccess();
    short count = 0;

    for (short index = 0; index < itemsLength; index++) {
      if (Util.getShort(items[index].index, INDEX_TYPE_OFFSET) != type) {
        count++;
      }
    }

    if (count == itemsLength) {
      return;
    }

    SafeItem[] remaining = new SafeItem[count == 0 ? ITEM_LENGTH_EXTENSION : count];
    short position = 0;

    for (short index = 0; index < itemsLength; index++) {
      SafeItem item = items[index];

      if (Util.getShort(item.index, INDEX_TYPE_OFFSET) != type) {
        remaining[position++] = item;
      }
    }

    Object revision = new Object();
    boolean transaction = JCSystem.getTransactionDepth() == 0;

    if (transaction) {
      JCSystem.beginTransaction();
    }

    try {
      items = remaining;
      itemsLength = count;
      itemsRevision = revision;

      if (transaction) {
        JCSystem.commitTransaction();
      }
    } finally {
      if (transaction && JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }

    JCSystem.requestObjectDeletion();
  }

  public void checkAccess() {
    clearAuth();
    Command.requireAuth();

    if (getPINSetResult(SAFE_FALSE) != SAFE_TRUE) {
      MonoidException.throwIt(MonoidException.CODE_SECRET_PIN_NOT_SET);
    }

    if (getPINBlockedResult() != SAFE_FALSE) {
      MonoidException.throwIt(MonoidException.CODE_SECRET_PIN_BLOCKED);
    }

    auth[0] = 0;
    auth[1] = (short) ~AUTH_ACCESS;
    auth[0] = AUTH_ACCESS;

    assertAccess();
  }

  public void assertAccess() {
    if (session[0] != null) {
      ((MonoidSession) session[0]).assertActive();
      return;
    }

    // Identity encryption calls back into storage; this guard must remain local.
    if (LibSecurity.check(authorizationValidation, SAFE_FALSE) != SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  void beginSession(MonoidSession authorized) {
    authorized.assertActive();

    // A client data callback cannot start another storage operation inside this one.
    if (session[0] != null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    session[0] = authorized;
  }

  void endSession() {
    session[0] = null;
  }

  void checkStorage(short length) {
    JCSystem.getAvailableMemory(availableMemory, (short) 0, JCSystem.MEMORY_TYPE_PERSISTENT);
    short required = (short) (MIN_AVAILABLE_PERSISTENT_MEMORY + length);

    // The two shorts contain an unsigned 32-bit count, most significant half first.
    if (
      availableMemory[0] == 0 &&
      (short) (availableMemory[1] ^ (short) 0x8000) < (short) (required ^ (short) 0x8000)
    ) {
      JCSystem.requestObjectDeletion();
      ISOException.throwIt(ISO7816.SW_FILE_FULL);
    }
  }

  private void clearAuth() {
    auth[0] = 0;
    auth[1] = 0;
  }

  public static short type(byte[] buffer, short offset, short length) throws MonoidException {
    if (Utils.isEqual(TYPE_TEXT_ENTROPY, buffer, offset, length)) {
      return TYPE_ENTROPY;
    } else if (Utils.isEqual(TYPE_TEXT_SEED, buffer, offset, length)) {
      return TYPE_SEED;
    } else if (Utils.isEqual(TYPE_TEXT_SECP256K1, buffer, offset, length)) {
      return TYPE_WEIERSTRASS_SECP256K1;
    } else if (Utils.isEqual(TYPE_TEXT_SECP256R1, buffer, offset, length)) {
      return TYPE_WEIERSTRASS_SECP256R1;
    } else if (Utils.isEqual(TYPE_TEXT_ED25519, buffer, offset, length)) {
      return TYPE_EDWARDS_ED25519;
    } else if (Utils.isEqual(TYPE_TEXT_HMAC, buffer, offset, length)) {
      return TYPE_HMAC;
    }

    MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    return 0;
  }

  public static short type(byte[] type) throws MonoidException {
    return type(type, (short) 0, (short) type.length);
  }

  public static byte[] type(short type) throws MonoidException {
    switch (type & TYPE_CATEGORY_MASK) {
      case TYPE_ENTROPY:
        return TYPE_TEXT_ENTROPY;
      case TYPE_SEED:
        return TYPE_TEXT_SEED;
      case TYPE_HMAC:
        return TYPE_TEXT_HMAC;
      case TYPE_WEIERSTRASS:
      case TYPE_EDWARDS:
        switch (type) {
          case TYPE_WEIERSTRASS_SECP256K1:
            return TYPE_TEXT_SECP256K1;
          case TYPE_WEIERSTRASS_SECP256R1:
            return TYPE_TEXT_SECP256R1;
          case TYPE_EDWARDS_ED25519:
            return TYPE_TEXT_ED25519;
          default:
            return null;
        }
      default:
        return null;
    }
  }

  public static short type(CBORReader reader) throws MonoidException {
    return type(reader.text());
  }

  public static boolean isTypeSeed(short type) {
    return (type & TYPE_CATEGORY_MASK) == (TYPE_SEED & TYPE_CATEGORY_MASK);
  }

  public static boolean isTypeWeierstrass(short type) {
    return (type & TYPE_CATEGORY_MASK) == (TYPE_WEIERSTRASS & TYPE_CATEGORY_MASK);
  }

  public static boolean isTypeHmac(short type) {
    return (type & TYPE_CATEGORY_MASK) == TYPE_HMAC;
  }

  static short getMappedKeyType(short type) {
    for (short offset = 0; offset < MAPPED_KEY_TYPES.length; offset += 2) {
      if (MAPPED_KEY_TYPES[offset] == type) {
        return MAPPED_KEY_TYPES[(short) (offset + 1)];
      }
    }

    return 0;
  }

  public static boolean isKnownExplicitLengthType(short type) {
    switch (type & TYPE_CATEGORY_MASK) {
      case TYPE_ENTROPY:
      case TYPE_SEED:
      case TYPE_HMAC:
        return true;
      default:
        return false;
    }
  }

  public static boolean isKnownDigestIndexedType(short type) {
    switch (type & TYPE_CATEGORY_MASK) {
      case TYPE_ENTROPY:
      case TYPE_SEED:
      case TYPE_WEIERSTRASS:
      case TYPE_EDWARDS:
      case TYPE_HMAC:
        return true;
      default:
        return getMappedKeyType(type) != 0;
    }
  }

  private byte[] buildDigestIndex(short refinedType, SafeDataSource data) {
    byte[] index = new byte[Safe.INDEX_LENGTH];

    Util.setShort(index, Safe.INDEX_TYPE_OFFSET, refinedType);

    byte[] digest = new byte[MessageDigest.LENGTH_SHA_256];

    short length = data.getLength();
    byte[] buffer = new byte[Utils.min(length, (short) 256)];

    if (length <= buffer.length) {
      data.read((short) 0, buffer, (short) 0, length);
      OneShot.digest(MessageDigest.ALG_SHA_256, buffer, (short) 0, length, digest, (short) 0);
    } else {
      if (indexDigest == null) {
        indexDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
      }

      indexDigest.reset();

      for (short offset = 0; offset < length; ) {
        short chunkLength = Utils.min((short) (length - offset), (short) buffer.length);
        data.read(offset, buffer, (short) 0, chunkLength);
        offset += chunkLength;

        if (offset == length) {
          indexDigest.doFinal(buffer, (short) 0, chunkLength, digest, (short) 0);
        } else {
          indexDigest.update(buffer, (short) 0, chunkLength);
        }
      }
    }

    Util.arrayCopyNonAtomic(digest, (short) 0, index, Safe.INDEX_ID_OFFSET, Safe.INDEX_ID_LENGTH);

    return index;
  }

  private static short refineType(short type, SafeDataSource data) throws SafeException {
    short mappedType = getMappedKeyType(type);

    if (mappedType != 0) {
      refineType(mappedType, data);
      return type;
    }

    short length = data.getLength();

    switch (type) {
      case TYPE_WEIERSTRASS_SECP256K1:
        if (length != CurveSECP256k1.KEY_LENGTH || Utils.isZero(data.duplicateAsPersistent())) {
          SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        }

        return type;
      case TYPE_WEIERSTRASS_SECP256R1:
        if (
          length != CurveSECP256r1.KEY_LENGTH ||
          !isValidScalar(data.duplicateAsPersistent(), CurveSECP256r1.R)
        ) {
          SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        }

        return type;
      case TYPE_EDWARDS_ED25519:
        if (length != CurveED25519.KEY_LENGTH) {
          SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        }

        return type;
      case TYPE_GENERIC:
        return type;
      case TYPE_RESERVED_EXTENSION_MARK:
        SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        return 0;
    }

    if ((type & TYPE_MASK) >= (TYPE_RESERVED_END & TYPE_MASK)) {
      return type;
    }

    switch (type & TYPE_CATEGORY_MASK) {
      case TYPE_ENTROPY:
      case TYPE_SEED:
      case TYPE_HMAC: {
        if (isTypeHmac(type) && (length < 1 || length > TYPE_METADATA_MASK)) {
          SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        }

        short specifiedKeyLength = (short) (type & TYPE_METADATA_MASK);

        if (specifiedKeyLength != 0 && specifiedKeyLength != length) {
          SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        }

        return (short) (type | length);
      }
    }

    SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
    return type;
  }

  private static boolean isValidScalar(byte[] data, byte[] order) {
    return (
      data.length == order.length &&
      !Utils.isZero(data) &&
      LibMath.compare(data, (short) 0, order, (short) 0, (short) order.length) < 0
    );
  }
}
