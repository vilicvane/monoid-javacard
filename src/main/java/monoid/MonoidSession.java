package monoid;

import static monoid.Constants.SAFE_FALSE;
import static monoid.Constants.SAFE_TRUE;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import monoidlib.LibSecurity;
import monoidlib.Utils;

final class MonoidSession implements Monoid {

  // @formatter:off
  private static final byte[] CONTEXT_LABEL = {'m','o','n','o','i','d',' ','a','p','p','l','e','t',':',' '};
  // @formatter:on

  private final Safe safe;
  private final Keystore keystore;
  private final AppletGrant grant;
  private SafeItem seedItem;
  private Object seedRevision;
  private byte[] seedData;
  private byte[] framedContext;
  private DerivedKey derivedKey;
  private final Object[] caller = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );
  private final short[] auth = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);

  private final LibSecurity.Condition authorizationValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      assertCurrent();
      return auth[0] == SAFE_TRUE && auth[1] == SAFE_FALSE;
    }
  };

  MonoidSession(Safe safe, Keystore keystore, AID caller, AppletGrant grant) {
    this.safe = safe;
    this.keystore = keystore;
    this.grant = grant;
    this.caller[0] = caller;
  }

  boolean matches(AID caller, AppletGrant grant) {
    return caller != null && this.caller[0] == caller && this.grant == grant;
  }

  void clearAuthentication() {
    auth[0] = 0;
    auth[1] = 0;
  }

  @Override
  public void authenticate(byte[] token) {
    authenticate(token, (short) 0, token == null ? 0 : (short) token.length);
  }

  @Override
  public void authenticate(byte[] token, short offset) {
    authenticate(token, offset, MessageDigest.LENGTH_SHA_256);
  }

  private void authenticate(byte[] token, short offset, short length) {
    clearAuthentication();
    assertCurrent();

    if (length != MessageDigest.LENGTH_SHA_256) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    assertRange(token, offset, length);
    if (safe.getAppletGrants().getTokenValidationResult(grant, token, offset) != SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    assertCurrent();
    auth[1] = SAFE_FALSE;
    auth[0] = SAFE_TRUE;
    assertActive();
  }

  @Override
  public short getMonoid001PublicKey(byte[] context, byte[] dest, short offset) {
    return getMonoid001PublicKey(
      context,
      (short) 0,
      context == null ? 0 : (short) context.length,
      dest,
      offset
    );
  }

  @Override
  public short getMonoid001PublicKey(
    byte[] context,
    short contextOffset,
    short contextLength,
    byte[] dest,
    short offset
  ) {
    begin();

    try {
      assertRange(dest, offset, (short) 65);
      DerivedKey derived = requireDerivedKey(context, contextOffset, contextLength);
      byte[] publicKey = keystore.getMonoid001UncompressedPublicKey(derived);
      assertActive();
      Util.arrayCopyNonAtomic(publicKey, (short) 0, dest, offset, (short) publicKey.length);
      return (short) publicKey.length;
    } catch (MonoidException exception) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      return 0;
    } catch (CryptoException exception) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      return 0;
    } finally {
      end();
    }
  }

  @Override
  public short signMonoid001ECDSADigest(byte[] context, byte[] digest, byte[] dest, short offset) {
    return signMonoid001ECDSADigest(
      context,
      (short) 0,
      context == null ? 0 : (short) context.length,
      digest,
      (short) 0,
      digest == null ? 0 : (short) digest.length,
      dest,
      offset
    );
  }

  @Override
  public short signMonoid001ECDSADigest(
    byte[] context,
    short contextOffset,
    short contextLength,
    byte[] digest,
    short digestOffset,
    byte[] dest,
    short offset
  ) {
    return signMonoid001ECDSADigest(
      context,
      contextOffset,
      contextLength,
      digest,
      digestOffset,
      MessageDigest.LENGTH_SHA_256,
      dest,
      offset
    );
  }

  private short signMonoid001ECDSADigest(
    byte[] context,
    short contextOffset,
    short contextLength,
    byte[] digest,
    short digestOffset,
    short digestLength,
    byte[] dest,
    short offset
  ) {
    begin();

    // Release the session before mapping crypto errors; this also bounds CAP handler gaps.
    try {
      try {
        assertRange(dest, offset, (short) 64);

        if (digestLength != MessageDigest.LENGTH_SHA_256) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        assertRange(digest, digestOffset, digestLength);
        DerivedKey derived = requireDerivedKey(context, contextOffset, contextLength);
        byte[] signature = keystore.signMonoid001ECDSADigest(derived, digest, digestOffset);
        assertActive();
        Util.arrayCopyNonAtomic(signature, (short) 0, dest, offset, (short) 64);
        return 64;
      } finally {
        end();
      }
    } catch (MonoidException exception) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      return 0;
    } catch (CryptoException exception) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      return 0;
    }
  }

  @Override
  public SafeItemIteratorShareable list(short type) {
    return list(type, null);
  }

  @Override
  public SafeItemIteratorShareable list(short type, byte[] keyPrefix) {
    begin();

    try {
      return new SafeSessionIterator(
        this,
        safe.list(type, keyPrefix, grant),
        safe.getItemsRevision()
      );
    } finally {
      end();
    }
  }

  @Override
  public SafeItemShareable get(byte[] index) {
    begin();

    try {
      assertIndex(index, false);
      SafeItem item = safe.get(index);
      return item == null ? null : new SafeSessionItem(this, item, safe.getItemsRevision());
    } finally {
      end();
    }
  }

  @Override
  public SafeDataShareable getData(
    byte[] index,
    short indexOffset,
    byte[] expectedKey,
    short keyOffset,
    short keyLength
  ) {
    begin();
    SafeDataShareable snapshot = null;

    try {
      assertIndex(index, indexOffset, false);
      assertKeyRange(expectedKey, keyOffset, keyLength);
      SafeItem item = safe.get(index, indexOffset);

      if (item != null) {
        byte[] data = requireReadableData(item);

        if (matchesKey(item, expectedKey, keyOffset, keyLength)) {
          snapshot = new SafeSessionData(this, item, data, safe.getItemsRevision());
        }
      }
    } finally {
      end();
    }

    return snapshot;
  }

  @Override
  public boolean isDataCurrent(SafeDataShareable data) {
    begin();

    try {
      return data instanceof SafeSessionData && ((SafeSessionData) data).isCurrent(this);
    } catch (ISOException exception) {
      // Map stale data at the API boundary; a typed catch here also bounds CAP handler gaps.
      if (exception.getReason() == ISO7816.SW_CONDITIONS_NOT_SATISFIED) {
        return false;
      }
      throw exception;
    } finally {
      end();
    }
  }

  @Override
  public short listIndices(
    short type,
    byte[] keyPrefix,
    short keyOffset,
    short keyLength,
    byte[] dest,
    short offset,
    short capacity
  ) {
    begin();

    try {
      assertKeyRange(keyPrefix, keyOffset, keyLength);
      if (capacity < 0 || capacity > (short) (0x7FFF / Safe.INDEX_LENGTH)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      short length = (short) (capacity * Safe.INDEX_LENGTH);
      assertRange(dest, offset, length);
      if (
        keyPrefix == dest &&
        keyLength != 0 &&
        length != 0 &&
        keyOffset < (short) (offset + length) &&
        offset < (short) (keyOffset + keyLength)
      ) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      return safe.listIndices(type, keyPrefix, keyOffset, keyLength, dest, offset, capacity, grant);
    } finally {
      end();
    }
  }

  @Override
  public short readData(
    byte[] index,
    byte[] expectedKey,
    byte[] dest,
    short offset,
    short capacity
  ) {
    return readData(
      index,
      (short) 0,
      index == null ? 0 : (short) index.length,
      expectedKey,
      (short) 0,
      expectedKey == null ? 0 : (short) expectedKey.length,
      dest,
      offset,
      capacity
    );
  }

  @Override
  public short readData(
    byte[] index,
    short indexOffset,
    byte[] expectedKey,
    short keyOffset,
    short keyLength,
    byte[] dest,
    short offset,
    short capacity
  ) {
    return readData(
      index,
      indexOffset,
      Safe.INDEX_LENGTH,
      expectedKey,
      keyOffset,
      keyLength,
      dest,
      offset,
      capacity
    );
  }

  private short readData(
    byte[] index,
    short indexOffset,
    short indexLength,
    byte[] expectedKey,
    short keyOffset,
    short keyLength,
    byte[] dest,
    short offset,
    short capacity
  ) {
    begin();
    // One exit keeps javac from duplicating finally handlers in the CAP exception table.
    short length = -1;

    try {
      if (indexLength != Safe.INDEX_LENGTH) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      assertIndex(index, indexOffset, false);
      assertKeyRange(expectedKey, keyOffset, keyLength);
      assertRange(dest, offset, capacity);
      SafeItem item = safe.get(index, indexOffset);

      if (item != null) {
        byte[] data = requireReadableData(item);

        if (matchesKey(item, expectedKey, keyOffset, keyLength)) {
          length = (short) data.length;
          Util.arrayCopyNonAtomic(data, (short) 0, dest, offset, Utils.min(capacity, length));
        }
      }
    } finally {
      end();
    }

    return length;
  }

  @Override
  public SafeItemShareable create(
    byte[] index,
    byte[] key,
    byte[] alias,
    SafeDataShareable data,
    boolean secret
  ) {
    begin();
    SafeSessionSource source = null;

    try {
      assertIndex(index, true);
      source = new SafeSessionSource(this, data);
      SafeItem item = safe.create(index, key, alias, source, secret);
      return item == null ? null : new SafeSessionItem(this, item, safe.getItemsRevision());
    } finally {
      if (source != null) {
        source.close();
      }

      end();
    }
  }

  @Override
  public void removeAll(short type) {
    begin();

    try {
      if (!grant.allows(type, true)) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      safe.removeAll(type);
    } finally {
      end();
    }
  }

  @Override
  public boolean createData(
    byte[] index,
    short indexOffset,
    byte[] key,
    short keyOffset,
    short keyLength,
    byte[] alias,
    byte[] data,
    short dataOffset,
    short dataLength,
    boolean secret
  ) {
    begin();

    try {
      assertIndex(index, indexOffset, true);
      assertKeyRange(key, keyOffset, keyLength);
      assertRange(data, dataOffset, dataLength);
      return safe.createData(
        index,
        indexOffset,
        key,
        keyOffset,
        keyLength,
        alias,
        data,
        dataOffset,
        dataLength,
        secret
      );
    } finally {
      end();
    }
  }

  void begin() {
    safe.beginSession(this);
  }

  void end() {
    safe.endSession();
  }

  Safe getSafe() {
    return safe;
  }

  void assertActive() {
    if (LibSecurity.check(authorizationValidation, SAFE_FALSE) != SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  Object requireItemRevision(SafeItem item, boolean write, Object revision) {
    assertActive();
    assertIndex(item.index, write);
    Object current = safe.getItemsRevision();

    if (current != revision && safe.get(item.index) != item) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    return current;
  }

  void assertItemsRevision(Object revision) {
    assertActive();

    if (safe.getItemsRevision() != revision) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  byte[] requireReadableData(SafeItem item) {
    assertActive();
    assertIndex(item.index, false);

    if (item.getSecretValue() != SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    return item.getStoredData();
  }

  static boolean matchesKey(SafeItem item, byte[] expectedKey, short keyOffset, short keyLength) {
    return item.key == null
      ? expectedKey == null
      : expectedKey != null && Utils.isEqual(item.key, expectedKey, keyOffset, keyLength);
  }

  static void assertKeyRange(byte[] key, short offset, short length) {
    if (key == null) {
      if (offset != 0 || length != 0) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    } else {
      assertRange(key, offset, length);
    }
  }

  static void assertRange(byte[] buffer, short offset, short length) {
    if (buffer == null || offset < 0 || length < 0 || offset > (short) (buffer.length - length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  private void assertCurrent() {
    AID actual = JCSystem.getPreviousContextAID();

    if (caller[0] == null || actual != caller[0] || !safe.getAppletGrants().contains(grant)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  private void assertIndex(byte[] index, boolean write) {
    if (index == null || index.length != Safe.INDEX_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    assertIndex(index, (short) 0, write);
  }

  private void assertIndex(byte[] index, short offset, boolean write) {
    assertRange(index, offset, Safe.INDEX_LENGTH);

    if (!grant.allows(Util.getShort(index, (short) (offset + Safe.INDEX_TYPE_OFFSET)), write)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  private byte[] requireSeed() {
    if (grant.seed == null) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // Directory revisions cover removal/replacement; data updates publish a new private array.
    Object revision = safe.getItemsRevision();
    if (seedRevision != revision) {
      seedItem = safe.get(grant.seed.index);
      seedRevision = revision;
    } else {
      safe.assertAccess();
    }

    if (
      seedItem == null ||
      !Safe.isTypeSeed(Util.getShort(seedItem.index, Safe.INDEX_TYPE_OFFSET)) ||
      seedItem.getStoredData().length != Keystore.SEED_512_LENGTH
    ) {
      seedData = null;
      derivedKey = null;
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] data = seedItem.getStoredData();
    if (seedData != data) {
      derivedKey = null;
      seedData = data;
    }

    return data;
  }

  private DerivedKey requireDerivedKey(byte[] context, short offset, short length) {
    byte[] seed = requireSeed();
    byte[] input = createContext(context, offset, length);

    if (derivedKey == null) {
      derivedKey = keystore.deriveMonoid001Key(seed, input);
    }

    return derivedKey;
  }

  private byte[] createContext(byte[] context, short offset, short contextLength) {
    assertRange(context, offset, contextLength);
    short prefixLength = (short) (CONTEXT_LABEL.length + 2 + grant.seed.domain.length);
    short maxLength = (short) (0x7FFF - Monoid001Derivation.MASTER_KEY_LABEL.length - 3);

    // Leave room for Monoid-001's label and rejection-sampling suffix.
    if (prefixLength < 0 || contextLength > (short) (maxLength - prefixLength)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // The grant/domain is fixed, and the derivation cache copies its input. Reuse only our
    // private frame; never retain the caller's global array. Reset also expires this session.
    short length = (short) (prefixLength + contextLength);

    if (framedContext == null || framedContext.length != length) {
      derivedKey = null;
      byte[] input = new byte[length];
      Util.arrayCopyNonAtomic(
        CONTEXT_LABEL,
        (short) 0,
        input,
        (short) 0,
        (short) CONTEXT_LABEL.length
      );
      Util.setShort(input, (short) CONTEXT_LABEL.length, (short) grant.seed.domain.length);
      Util.arrayCopyNonAtomic(
        grant.seed.domain,
        (short) 0,
        input,
        (short) (CONTEXT_LABEL.length + 2),
        (short) grant.seed.domain.length
      );
      Util.arrayCopyNonAtomic(context, offset, input, prefixLength, contextLength);
      framedContext = input;

      // A warm caller may skip collection; replacing a private frame must not strand its old one.
      if (JCSystem.isObjectDeletionSupported()) {
        JCSystem.requestObjectDeletion();
      }
    } else if (
      Util.arrayCompare(context, offset, framedContext, prefixLength, contextLength) != 0
    ) {
      derivedKey = null;
      Util.arrayCopyNonAtomic(context, offset, framedContext, prefixLength, contextLength);
    }

    return framedContext;
  }
}
