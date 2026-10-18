package monoid;

import static monoidsafe.Constants.SAFE_FALSE;
import static monoidsafe.Constants.SAFE_TRUE;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import monoidsafe.SafeItemIteratorShareable;
import monoidsafe.SafeItemShareable;
import monoidsafe.SafeShareable;

/**
 * The `Safe` class is a `MonoidSafe` wrapper that validates known data types
 * and provides utility methods.
 */
public final class Safe {

  public static final short TYPE_MASK = (short) 0xFFFF;
  public static final short TYPE_CATEGORY_MASK = (short) 0xFF00;
  public static final short TYPE_METADATA_MASK = 0x00FF;
  public static final short TYPE_RESERVED_END = 0x1000;

  public static final short TYPE_ENTROPY = 0x0100;
  public static final short TYPE_SEED = 0x0200;
  public static final short TYPE_MASTER = 0x0300;
  public static final short TYPE_WEIERSTRASS = 0x0400;
  public static final short TYPE_WEIERSTRASS_SECP256K1 = TYPE_WEIERSTRASS | 0x01;
  public static final short TYPE_WEIERSTRASS_SECP256R1 = TYPE_WEIERSTRASS | 0x02;
  public static final short TYPE_EDWARDS = 0x0500;
  public static final short TYPE_EDWARDS_ED25519 = TYPE_EDWARDS | 0x01;
  public static final short TYPE_GENERIC = 0x0FFF;
  public static final short TYPE_RESERVED_EXTENSION_MARK = (short) 0xFFFF;

  // @formatter:off
  public static final byte[] TYPE_TEXT_ENTROPY = {'e','n','t','r','o','p','y'};
  public static final byte[] TYPE_TEXT_SEED = {'s','e','e','d'};
  public static final byte[] TYPE_TEXT_MASTER = {'m','a','s','t','e','r'};
  public static final byte[] TYPE_TEXT_SECP256K1 = {'s','e','c','p','2','5','6','k','1'};
  public static final byte[] TYPE_TEXT_SECP256R1 = {'s','e','c','p','2','5','6','r','1'};
  public static final byte[] TYPE_TEXT_ED25519 = {'e','d','2','5','5','1','9'};
  // @formatter:on

  private SafeShareable safe;

  private final LibSecurity.Condition pinSetValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return safe.isPINSet();
    }
  };
  private final LibSecurity.Condition pinValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return safe.isPINValidated();
    }
  };
  private final LibSecurity.Condition pinBlocked = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return safe.getPINTriesRemaining() == 0;
    }
  };

  public Safe(SafeShareable safe) {
    this.safe = safe;
  }

  public byte[] getId() {
    return safe.getId();
  }

  public byte[] getPublicKey() {
    return safe.getPublicKey();
  }

  public boolean isPINSet() {
    return safe.isPINSet();
  }

  short getPINSetResult(short conservativeResult) {
    return LibSecurity.check(pinSetValidation, conservativeResult);
  }

  short getPINValidationResult() {
    return LibSecurity.check(pinValidation, SAFE_FALSE);
  }

  short getPINBlockedResult() {
    return LibSecurity.check(pinBlocked, SAFE_TRUE);
  }

  public boolean checkPIN(byte[] pin) {
    pin = Utils.duplicateAsGlobal(pin);
    return safe.checkPIN(pin, (short) 0, (byte) pin.length);
  }

  public void updatePIN(byte[] pin) {
    pin = Utils.duplicateAsGlobal(pin);
    safe.updatePIN(pin, (short) 0, (byte) pin.length);
  }

  public short getPINTriesRemaining() {
    return safe.getPINTriesRemaining();
  }

  public SafeItemShareable createKnownRandom(short type) throws SafeException {
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
      case TYPE_MASTER: {
        short keyLength = (short) (type & TYPE_METADATA_MASK);

        if (keyLength == 0) {
          SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        }

        return createRandomRandom(type, (short) (keyLength * 2));
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
  private SafeItemShareable createRandomRandom(short refinedType, short length) {
    byte[] data = Utils.makeGlobalByteArray(length);

    OneShot.random(data, (short) 0, length);

    byte[] index = buildGlobalDigestIndex(refinedType, data);

    return safe.create(index, null, null, data, true);
  }

  private SafeItemShareable createRandomScalar(short refinedType, byte[] order) {
    byte[] data = Utils.makeGlobalByteArray((short) order.length);

    do {
      OneShot.random(data, (short) 0, (short) data.length);
    } while (!isValidScalar(data, order));

    byte[] index = buildGlobalDigestIndex(refinedType, data);

    return safe.create(index, null, null, data, true);
  }

  public SafeItemIteratorShareable list(short type) {
    return safe.list(type);
  }

  public SafeItemIteratorShareable list(short type, byte[] keyPrefix) {
    keyPrefix = keyPrefix != null ? Utils.duplicateAsGlobal(keyPrefix) : null;

    return safe.list(type, keyPrefix);
  }

  public SafeItemShareable get(byte[] index) {
    index = Utils.duplicateAsGlobal(index);

    return safe.get(index);
  }

  public SafeItemShareable require(byte[] index) {
    SafeItemShareable item = get(index);

    if (item == null) {
      SafeException.throwIt(SafeException.REASON_NOT_FOUND);
    }

    return item;
  }

  public SafeItemShareable create(short type, byte[] key, byte[] alias, byte[] data, boolean secret)
    throws SafeException {
    if (!isKnownDigestIndexedType(type)) {
      SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
    }

    type = refineType(type, data);

    byte[] index = buildGlobalDigestIndex(type, data);

    key = key != null ? Utils.duplicateAsGlobal(key) : null;
    alias = alias != null ? Utils.duplicateAsGlobal(alias) : null;
    data = Utils.duplicateAsGlobal(data);

    return safe.create(index, key, alias, data, secret);
  }

  public SafeItemShareable create(
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] data,
    boolean secret
  ) {
    if (index.length != SafeShareable.INDEX_LENGTH) {
      SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
    }

    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    byte[] builtIndex;

    if (isKnownDigestIndexedType(type)) {
      if (type != refineType(type, data)) {
        SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
      }

      builtIndex = buildGlobalDigestIndex(type, data);

      // Validate digest.
      if (
        Util.arrayCompare(
          index,
          SafeShareable.INDEX_ID_OFFSET,
          builtIndex,
          SafeShareable.INDEX_ID_OFFSET,
          SafeShareable.INDEX_ID_LENGTH
        ) !=
        0
      ) {
        SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
      }
    } else {
      builtIndex = Utils.duplicateAsGlobal(index);
    }

    key = key != null ? Utils.duplicateAsGlobal(key) : null;
    alias = alias != null ? Utils.duplicateAsGlobal(alias) : null;
    data = Utils.duplicateAsGlobal(data);

    return safe.create(builtIndex, key, alias, data, secret);
  }

  /** The request arrays must be global for the Safe Shareable call. */
  public void importItem(
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] senderPublicKey,
    byte[] data
  ) {
    safe.importItem(index, key, alias, senderPublicKey, data);
  }

  public static short type(byte[] buffer, short offset, short length) throws MonoidException {
    if (Utils.isEqual(TYPE_TEXT_ENTROPY, buffer, offset, length)) {
      return TYPE_ENTROPY;
    } else if (Utils.isEqual(TYPE_TEXT_SEED, buffer, offset, length)) {
      return TYPE_SEED;
    } else if (Utils.isEqual(TYPE_TEXT_MASTER, buffer, offset, length)) {
      return TYPE_MASTER;
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
      case TYPE_MASTER:
        return TYPE_TEXT_MASTER;
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

  public static boolean isTypeMaster(short type) {
    return (type & TYPE_CATEGORY_MASK) == (TYPE_MASTER & TYPE_CATEGORY_MASK);
  }

  public static boolean isTypeWeierstrass(short type) {
    return (type & TYPE_CATEGORY_MASK) == (TYPE_WEIERSTRASS & TYPE_CATEGORY_MASK);
  }

  public static boolean isKnownExplicitLengthType(short type) {
    switch (type & TYPE_CATEGORY_MASK) {
      case TYPE_ENTROPY:
      case TYPE_SEED:
      case TYPE_MASTER:
        return true;
      default:
        return false;
    }
  }

  public static boolean isKnownDigestIndexedType(short type) {
    switch (type & TYPE_CATEGORY_MASK) {
      case TYPE_ENTROPY:
      case TYPE_SEED:
      case TYPE_MASTER:
      case TYPE_WEIERSTRASS:
      case TYPE_EDWARDS:
        return true;
      default:
        return false;
    }
  }

  private static byte[] buildGlobalDigestIndex(short refinedType, byte[] data) {
    byte[] index = Utils.makeGlobalByteArray(SafeShareable.INDEX_LENGTH);

    Util.setShort(index, SafeShareable.INDEX_TYPE_OFFSET, refinedType);

    byte[] digest = JCSystem.makeTransientByteArray(
      MessageDigest.LENGTH_SHA_256,
      JCSystem.CLEAR_ON_DESELECT
    );

    OneShot.digest(
      MessageDigest.ALG_SHA_256,
      data,
      (short) 0,
      (short) data.length,
      digest,
      (short) 0
    );

    Util.arrayCopyNonAtomic(
      digest,
      (short) 0,
      index,
      SafeShareable.INDEX_ID_OFFSET,
      SafeShareable.INDEX_ID_LENGTH
    );

    return index;
  }

  private static short refineType(short type, byte[] data) throws SafeException {
    switch (type) {
      case TYPE_WEIERSTRASS_SECP256K1:
        if (data.length != CurveSECP256k1.KEY_LENGTH || Utils.isZero(data)) {
          SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        }

        return type;
      case TYPE_WEIERSTRASS_SECP256R1:
        if (!isValidScalar(data, CurveSECP256r1.R)) {
          SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        }

        return type;
      case TYPE_EDWARDS_ED25519:
        if (data.length != CurveED25519.KEY_LENGTH) {
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

        if (specifiedKeyLength != 0 && specifiedKeyLength != data.length) {
          SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        }

        return (short) (type | data.length);
      }
      case TYPE_MASTER: {
        short keyLength = (short) (data.length / 2);
        short specifiedKeyLength = (short) (type & TYPE_METADATA_MASK);

        if (
          (short) (keyLength * 2) != data.length ||
          (specifiedKeyLength != 0 && specifiedKeyLength != keyLength)
        ) {
          SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
        }

        return (short) (type | keyLength);
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
