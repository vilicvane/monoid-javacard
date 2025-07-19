package monoid;

import javacard.framework.*;

public final class Safe {
  public static final byte TYPE_SEED = 0x01;
  public static final byte TYPE_MASTER = 0x02;
  public static final byte TYPE_RAW = 0x03;

  public static final byte[] TYPE_TEXT_SEED = { 's', 'e', 'e', 'd' };
  public static final byte[] TYPE_TEXT_MASTER = { 'm', 'a', 's', 't', 'e', 'r' };
  public static final byte[] TYPE_TEXT_RAW = { 'r', 'a', 'w' };

  public static final byte INDEX_DIGEST_LENGTH = 8;
  public static final byte INDEX_LENGTH = 1 + INDEX_DIGEST_LENGTH;

  public static byte type(byte[] buffer, short offset, byte length) throws MonoidException {
    if (Utils.equal(TYPE_TEXT_SEED, buffer, offset, length)) {
      return TYPE_SEED;
    } else if (Utils.equal(TYPE_TEXT_MASTER, buffer, offset, length)) {
      return TYPE_MASTER;
    } else if (Utils.equal(TYPE_TEXT_RAW, buffer, offset, length)) {
      return TYPE_RAW;
    }

    MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    return 0;
  }

  public static byte type(byte[] type) throws MonoidException {
    return type(type, (short) 0, (byte) type.length);
  }

  public static byte[] type(byte type) throws MonoidException {
    switch (type) {
      case TYPE_SEED:
        return TYPE_TEXT_SEED;
      case TYPE_MASTER:
        return TYPE_TEXT_MASTER;
      case TYPE_RAW:
        return TYPE_TEXT_RAW;
      default:
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return null;
    }
  }

  public static byte type(CBORReader reader) throws MonoidException {
    byte[] buffer = JCSystem.makeTransientByteArray((short) 6, JCSystem.CLEAR_ON_DESELECT);

    short length = reader.text(buffer, (short) 0);

    return type(buffer, (short) 0, (byte) length);
  }
}
