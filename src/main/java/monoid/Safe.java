package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
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
  public static final short TYPE_EC = 0x0400;
  public static final short TYPE_EC_SECP256K1 = TYPE_EC | 0x01;
  public static final short TYPE_GENERIC = 0x0FFF;
  public static final short TYPE_RESERVED_EXTENSION_MARK = (short) 0xFFFF;

  // @formatter:off
  public static final byte[] TYPE_TEXT_ENTROPY = {'e','n','t','r','o','p','y'};
  public static final byte[] TYPE_TEXT_SEED = {'s','e','e','d'};
  public static final byte[] TYPE_TEXT_MASTER = {'m','a','s','t','e','r'};
  public static final byte[] TYPE_TEXT_SECP256K1 = {'s','e','c','p','2','5','6','k','1'};
  // @formatter:on

  private SafeShareable safe;

  public Safe(SafeShareable safe) {
    this.safe = safe;
  }

  public byte[] getId() {
    return safe.getId();
  }

  public boolean isPINSet() {
    return safe.isPINSet();
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
      case TYPE_EC_SECP256K1:
        return createRandomRandom(type, (short) CurveSECP256k1.KEY_LENGTH);
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
   * E.g., a valid SECP256K1 key ranges from 1 to 2 ^ 256 - 1, practically all
   * possible values of a 32-byte array is valid; a valid Ed25519 key on the
   * other hand ranges from 0 to 2 ^ 255 - 1, thus not a "random random".
   */
  private SafeItemShareable createRandomRandom(short refinedType, short length) {
    byte[] data = Utils.makeGlobalByteArray(length);

    OneShot.random(data, (short) 0, length);

    byte[] index = buildGlobalDigestIndex(refinedType, data);

    return safe.create(index, null, data);
  }

  public Object[] list(short type) {
    return safe.list(type);
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

  public SafeItemShareable create(short type, byte[] alias, byte[] data) throws SafeException {
    if (!isKnownDigestIndexedType(type)) {
      SafeException.throwIt(SafeException.REASON_INVALID_PARAMETER);
    }

    type = refineType(type, data);

    byte[] index = buildGlobalDigestIndex(type, data);

    data = Utils.duplicateAsGlobal(data);

    return safe.create(index, alias, data);
  }

  public SafeItemShareable create(byte[] index, byte[] alias, byte[] data) {
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

    data = Utils.duplicateAsGlobal(data);

    return safe.create(builtIndex, alias, data);
  }

  public static short type(byte[] buffer, short offset, byte length) throws MonoidException {
    if (Utils.isEqual(TYPE_TEXT_ENTROPY, buffer, offset, length)) {
      return TYPE_ENTROPY;
    } else if (Utils.isEqual(TYPE_TEXT_SEED, buffer, offset, length)) {
      return TYPE_SEED;
    } else if (Utils.isEqual(TYPE_TEXT_MASTER, buffer, offset, length)) {
      return TYPE_MASTER;
    } else if (Utils.isEqual(TYPE_TEXT_SECP256K1, buffer, offset, length)) {
      return TYPE_EC_SECP256K1;
    }

    MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    return 0;
  }

  public static short type(byte[] type) throws MonoidException {
    return type(type, (short) 0, (byte) type.length);
  }

  public static byte[] type(short type) throws MonoidException {
    switch (type & TYPE_CATEGORY_MASK) {
      case TYPE_ENTROPY:
        return TYPE_TEXT_ENTROPY;
      case TYPE_SEED:
        return TYPE_TEXT_SEED;
      case TYPE_MASTER:
        return TYPE_TEXT_MASTER;
      case TYPE_EC:
        switch (type) {
          case TYPE_EC_SECP256K1:
            return TYPE_TEXT_SECP256K1;
          default:
            return null;
        }
      default:
        return null;
    }
  }

  public static short type(CBORReader reader) throws MonoidException {
    byte[] buffer = JCSystem.makeTransientByteArray((short) 6, JCSystem.CLEAR_ON_DESELECT);

    short length = reader.text(buffer, (short) 0);

    return type(buffer, (short) 0, (byte) length);
  }

  public static boolean isTypeSeed(short type) {
    return (type & TYPE_CATEGORY_MASK) == (TYPE_SEED & TYPE_CATEGORY_MASK);
  }

  public static boolean isTypeMaster(short type) {
    return (type & TYPE_CATEGORY_MASK) == (TYPE_MASTER & TYPE_CATEGORY_MASK);
  }

  public static boolean isTypeEC(short type) {
    return (type & TYPE_CATEGORY_MASK) == (TYPE_EC & TYPE_CATEGORY_MASK);
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
      case TYPE_EC:
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
      case TYPE_EC_SECP256K1:
        if (data.length != CurveSECP256k1.KEY_LENGTH || Utils.isZero(data)) {
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
}
