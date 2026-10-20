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
  public static final short TYPE_GENERIC = 0x0FFF;
  public static final short TYPE_RESERVED_EXTENSION_MARK = (short) 0xFFFF;

  // @formatter:off
  public static final byte[] TYPE_TEXT_ENTROPY = {'e','n','t','r','o','p','y'};
  public static final byte[] TYPE_TEXT_SEED = {'s','e','e','d'};
  public static final byte[] TYPE_TEXT_SECP256K1 = {'s','e','c','p','2','5','6','k','1'};
  public static final byte[] TYPE_TEXT_SECP256R1 = {'s','e','c','p','2','5','6','r','1'};
  public static final byte[] TYPE_TEXT_ED25519 = {'e','d','2','5','5','1','9'};
  // @formatter:on

  public static final byte PIN_TRY_LIMIT = 5;
  public static final byte MAX_PIN_LENGTH = 16;

  private static final short AUTH_SAFE = (short) 0x5AFE;

  private static final short PIN_UNSET = (short) 0xA501;
  private static final short PIN_SET = (short) 0x5AFE;

  private static final short ITEM_LENGTH_EXTENSION = 8;
  private static final short MIN_AVAILABLE_PERSISTENT_MEMORY = 4096;

  private OwnerPIN pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_LENGTH);

  private final short[] auth = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);

  private final LibSecurity.Condition authorizationValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      if (auth[0] == 0 && auth[1] == 0) {
        return false;
      }

      if (auth[0] != AUTH_SAFE || auth[1] != (short) ~AUTH_SAFE) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      return true;
    }
  };

  private LibSecurity.Condition pinValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return pin.isValidated();
    }
  };

  private short pinState = PIN_UNSET;
  private short pinStateInverse = (short) ~PIN_UNSET;

  private final LibSecurity.Condition pinSetValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      short state = pinState;

      if ((state != PIN_UNSET && state != PIN_SET) || pinStateInverse != (short) ~state) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      return state == PIN_SET;
    }
  };

  private final LibSecurity.Condition pinBlockedValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return pin.getTriesRemaining() == 0;
    }
  };

  private SafeItem[] items = new SafeItem[ITEM_LENGTH_EXTENSION];

  private short itemsLength = 0;

  private final short[] availableMemory = JCSystem.makeTransientShortArray(
    (short) 2,
    JCSystem.CLEAR_ON_RESET
  );

  private MessageDigest indexDigest;
  private ItemCipher itemCipher;
  private byte[] identityToken;

  void initializeIdentity() {
    if (identityToken == null) {
      identityToken = Utils.duplicateAsPrivate(getIdentity().getToken());
    }
  }

  public byte[] getId() {
    return requireIdentity().getId();
  }

  public byte[] getPublicKey() {
    return requireIdentity().getPublicKey();
  }

  public byte[] getBundle() {
    return requireIdentity().getBundle();
  }

  public SafeDataSource createBundle(byte[] publicKeys) {
    Command.requireAuth(Command.AUTH_SAFE);
    checkAccess();

    return new ItemCipher.Result(
      this,
      requireIdentity().createBundle(Utils.duplicateAsGlobal(publicKeys))
    );
  }

  /** Both inputs must be global arrays for the Identity call. */
  public byte[] joinBundle(byte[] senderPublicKey, byte[] data) {
    Command.requireAuth(Command.AUTH_SAFE);
    checkAccess();

    return requireIdentity().joinBundle(senderPublicKey, data);
  }

  public void reset() {
    IdentityShareable identity = requireIdentity();
    SafeItem[] emptyItems = new SafeItem[ITEM_LENGTH_EXTENSION];
    OwnerPIN safePIN = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_LENGTH);
    OwnerPIN accessPIN = new OwnerPIN(MonoidApplet.PIN_TRY_LIMIT, MonoidApplet.MAX_PIN_LENGTH);
    JCSystem.beginTransaction();

    try {
      items = emptyItems;
      itemsLength = 0;
      pin = safePIN;
      pinState = PIN_UNSET;
      pinStateInverse = (short) ~PIN_UNSET;
      MonoidApplet.resetPIN(accessPIN);
      KeyDerivation.clearCache();
      identity.resetBundle();
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
    return pinSetValidation.check();
  }

  short getPINSetResult(short conservativeResult) {
    return LibSecurity.check(pinSetValidation, conservativeResult);
  }

  short getPINBlockedResult() {
    return LibSecurity.check(pinBlockedValidation, SAFE_TRUE);
  }

  public short getPINTriesRemaining() {
    return pin.getTriesRemaining();
  }

  public boolean checkPIN(byte[] pin) {
    return checkPIN(pin, (short) 0, (byte) pin.length);
  }

  public boolean checkPIN(byte[] buffer, short offset, byte length) {
    clearAuth();

    try {
      if (LibSecurity.check(pinSetValidation, SAFE_FALSE) != SAFE_TRUE) {
        return false;
      }

      if (!pin.check(buffer, offset, length)) {
        return false;
      }

      if (LibSecurity.check(pinValidation, SAFE_FALSE) != SAFE_TRUE) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      auth[0] = 0;
      auth[1] = (short) ~AUTH_SAFE;
      auth[0] = AUTH_SAFE;

      return true;
    } finally {
      if (LibSecurity.check(pinBlockedValidation, SAFE_TRUE) != SAFE_FALSE) {
        clearAuth();
      }
    }
  }

  public void updatePIN(byte[] pin) {
    updatePIN(pin, (short) 0, (byte) pin.length);
  }

  public void updatePIN(byte[] buffer, short offset, byte length) {
    checkPINUpdate();

    JCSystem.beginTransaction();

    try {
      checkPINUpdate();
      clearAuth();

      pin.update(buffer, offset, length);
      pinState = PIN_SET;
      pinStateInverse = (short) ~PIN_SET;

      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }
  }

  private void checkPINUpdate() {
    if (LibSecurity.check(pinSetValidation, SAFE_TRUE) != SAFE_FALSE) {
      assertAccess();
    }
  }

  public boolean isPINValidated() {
    return getPINValidationResult() == SAFE_TRUE;
  }

  short getPINValidationResult() {
    if (getPINSetResult(SAFE_FALSE) != SAFE_TRUE) {
      return SAFE_FALSE;
    }

    if (LibSecurity.check(authorizationValidation, SAFE_FALSE) != SAFE_TRUE) {
      return SAFE_FALSE;
    }

    return getPINBlockedResult() == SAFE_FALSE ? SAFE_TRUE : SAFE_FALSE;
  }

  public SafeItemIterator list(short type) {
    return list(type, null);
  }

  public SafeItemIterator list(short type, byte[] keyPrefix) {
    assertAccess();
    return new SafeItemIterator(this, items, itemsLength, type, keyPrefix);
  }

  public SafeItem get(byte[] index) {
    assertAccess();
    return getItem(index);
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
      case TYPE_SEED: {
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
    byte[] data = JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);

    OneShot.random(data, (short) 0, length);

    SafeData source = new SafeData(data);
    byte[] index = buildDigestIndex(refinedType, source);

    return createItem(index, null, null, source, true);
  }

  private SafeItem createRandomScalar(short refinedType, byte[] order) {
    byte[] data = JCSystem.makeTransientByteArray((short) order.length, JCSystem.CLEAR_ON_DESELECT);

    do {
      OneShot.random(data, (short) 0, (short) data.length);
    } while (!isValidScalar(data, order));

    SafeData source = new SafeData(data);
    byte[] index = buildDigestIndex(refinedType, source);

    return createItem(index, null, null, source, true);
  }

  public SafeItem require(byte[] index) {
    SafeItem item = get(index);

    if (item == null) {
      SafeException.throwIt(SafeException.REASON_NOT_FOUND);
    }

    return item;
  }

  public SafeItem create(short type, byte[] key, byte[] alias, SafeDataSource data, boolean secret)
    throws SafeException {
    if (!isKnownDigestIndexedType(type)) {
      SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
    }

    type = refineType(type, data);

    byte[] index = buildDigestIndex(type, data);

    return createItem(index, key, alias, data, secret);
  }

  public SafeItem create(
    byte[] index,
    byte[] key,
    byte[] alias,
    SafeDataSource data,
    boolean secret
  ) {
    if (index.length != Safe.INDEX_LENGTH) {
      SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
    }

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

    return createItem(builtIndex, key, alias, data, secret);
  }

  private SafeItem createItem(
    byte[] index,
    byte[] key,
    byte[] alias,
    SafeDataSource data,
    boolean secret
  ) {
    assertAccess();

    if (getItem(index) != null) {
      return null;
    }

    checkStorage(getItemStorageLength(index, key, alias, (short) 0));
    index = Utils.duplicateAsPersistent(index);
    key = key != null ? Utils.duplicateAsPersistent(key) : null;
    alias = alias != null ? Utils.duplicateAsPersistent(alias) : null;

    short dataLength = data.getLength();
    assertAccess();
    checkStorage((short) (dataLength + getItemTableExtensionLength()));
    byte[] storedData = Utils.duplicateAsPersistent(data, dataLength);
    assertAccess();

    if (getItem(index) != null) {
      return null;
    }

    short extensionLength = getItemTableExtensionLength();

    if (extensionLength > 0) {
      checkStorage(extensionLength);
    }

    return publishItem(index, key, alias, storedData, secret);
  }

  private short getItemStorageLength(byte[] index, byte[] key, byte[] alias, short dataLength) {
    short length = (short) (index.length + dataLength);

    if (key != null) {
      length += (short) key.length;
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
    byte[] key,
    byte[] alias,
    byte[] data,
    boolean secret
  ) {
    SafeItem item = new SafeItem(this, index, key, alias, data, secret);
    SafeItem[] updatedItems = items;

    if (itemsLength == items.length) {
      updatedItems = new SafeItem[(short) (items.length + ITEM_LENGTH_EXTENSION)];

      for (short itemIndex = 0; itemIndex < itemsLength; itemIndex++) {
        updatedItems[itemIndex] = items[itemIndex];
      }
    }

    boolean extended = updatedItems != items;

    JCSystem.beginTransaction();

    try {
      items = updatedItems;
      items[itemsLength++] = item;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
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
    byte[] key,
    byte[] alias,
    byte[] senderPublicKey,
    SafeDataSource data
  ) {
    assertAccess();

    // Reserve the cross-applet read buffer.
    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) 64);

    index = Utils.duplicateAsPrivate(index);
    key = key != null ? Utils.duplicateAsPrivate(key) : null;
    alias = alias != null ? Utils.duplicateAsPrivate(alias) : null;
    senderPublicKey = senderPublicKey != null ? Utils.duplicateAsPrivate(senderPublicKey) : null;

    CommunicationDataShareable plaintext = requireItemCipher().decrypt(
      requireIdentity(),
      index,
      key,
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
    SafeItem item = getItem(index);

    if (item != null) {
      if (
        item.secret != secret ||
        !equal(item.key, key) ||
        !equal(item.alias, alias) ||
        item.data.length != dataLength
      ) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }

      for (short offset = 0; offset < dataLength; ) {
        short length = Utils.min((short) (dataLength - offset), (short) buffer.length);
        plaintext.read((short) (ItemCipher.SECRET_LENGTH + offset), buffer, (short) 0, length);
        assertAccess();

        if (Util.arrayCompare(item.data, offset, buffer, (short) 0, length) != 0) {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        offset += length;
      }

      return;
    }

    checkStorage(getItemStorageLength(index, key, alias, dataLength));
    index = Utils.duplicateAsPersistent(index);
    key = key != null ? Utils.duplicateAsPersistent(key) : null;
    alias = alias != null ? Utils.duplicateAsPersistent(alias) : null;
    byte[] storedData = new byte[dataLength];

    for (short offset = 0; offset < dataLength; ) {
      short length = Utils.min((short) (dataLength - offset), (short) buffer.length);
      plaintext.read((short) (ItemCipher.SECRET_LENGTH + offset), buffer, (short) 0, length);
      Util.arrayCopyNonAtomic(buffer, (short) 0, storedData, offset, length);
      offset += length;
    }

    assertAccess();
    publishItem(index, key, alias, storedData, secret == SAFE_TRUE);
  }

  private static boolean equal(byte[] left, byte[] right) {
    return (
      left == right ||
      (left != null &&
        right != null &&
        left.length == right.length &&
        Util.arrayCompare(left, (short) 0, right, (short) 0, (short) left.length) == 0)
    );
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

    JCSystem.beginTransaction();

    for (short index = indexToDelete; index < (short) (itemsLength - 1); index++) {
      items[index] = items[(short) (index + 1)];
    }

    items[--itemsLength] = null;

    JCSystem.requestObjectDeletion();

    JCSystem.commitTransaction();
  }

  public void checkAccess() {
    Command.requireAuth();

    if (getPINSetResult(SAFE_FALSE) != SAFE_TRUE) {
      MonoidException.throwIt(MonoidException.CODE_SAFE_PIN_NOT_SET);
    }

    if (getPINBlockedResult() != SAFE_FALSE) {
      MonoidException.throwIt(MonoidException.CODE_SAFE_BLOCKED);
    }

    auth[0] = 0;
    auth[1] = (short) ~AUTH_SAFE;
    auth[0] = AUTH_SAFE;

    assertAccess();
  }

  public void assertAccess() {
    if (LibSecurity.check(pinSetValidation, SAFE_FALSE) != SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (LibSecurity.check(authorizationValidation, SAFE_FALSE) != SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (LibSecurity.check(pinBlockedValidation, SAFE_TRUE) != SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
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
    pin.reset();
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

  public static boolean isKnownExplicitLengthType(short type) {
    switch (type & TYPE_CATEGORY_MASK) {
      case TYPE_ENTROPY:
      case TYPE_SEED:
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
        return true;
      default:
        return false;
    }
  }

  private byte[] buildDigestIndex(short refinedType, SafeDataSource data) {
    byte[] index = JCSystem.makeTransientByteArray(Safe.INDEX_LENGTH, JCSystem.CLEAR_ON_RESET);

    Util.setShort(index, Safe.INDEX_TYPE_OFFSET, refinedType);

    byte[] digest = JCSystem.makeTransientByteArray(
      MessageDigest.LENGTH_SHA_256,
      JCSystem.CLEAR_ON_DESELECT
    );

    short length = data.getLength();
    byte[] buffer = JCSystem.makeTransientByteArray(
      Utils.min(length, (short) 256),
      JCSystem.CLEAR_ON_RESET
    );

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
    short length = data.getLength();

    switch (type) {
      case TYPE_WEIERSTRASS_SECP256K1:
        if (length != CurveSECP256k1.KEY_LENGTH || Utils.isZero(readData(data))) {
          SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        }

        return type;
      case TYPE_WEIERSTRASS_SECP256R1:
        if (
          length != CurveSECP256r1.KEY_LENGTH || !isValidScalar(readData(data), CurveSECP256r1.R)
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
      case TYPE_SEED: {
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

  public static byte[] readData(SafeDataSource data) {
    byte[] buffer = JCSystem.makeTransientByteArray(data.getLength(), JCSystem.CLEAR_ON_RESET);
    data.read((short) 0, buffer, (short) 0, (short) buffer.length);
    return buffer;
  }

  private static boolean isValidScalar(byte[] data, byte[] order) {
    return (
      data.length == order.length &&
      !Utils.isZero(data) &&
      LibMath.compare(data, (short) 0, order, (short) 0, (short) order.length) < 0
    );
  }
}
