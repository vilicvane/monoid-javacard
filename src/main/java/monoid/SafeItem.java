package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class SafeItem {

  private final Safe safe;

  public byte[] index;
  public byte[] key;
  public byte[] alias;
  public byte[] data;
  public short secret;

  public SafeItem(Safe safe, byte[] index, byte[] key, byte[] alias, byte[] data, boolean secret) {
    this.safe = safe;
    this.index = index;
    this.key = key;
    this.alias = alias;
    this.data = data;
    this.secret = secret ? Constants.SAFE_TRUE : Constants.SAFE_FALSE;
  }

  public boolean matches(byte[] index) {
    return (Util.arrayCompare(this.index, (short) 0, index, (short) 0, Safe.INDEX_LENGTH) == 0);
  }

  public boolean matches(short type) {
    byte high = (byte) (type >> 8);
    byte low = (byte) (type & 0xFF);

    if (low == 0) {
      if (high == 0) {
        return true;
      } else {
        return high == index[Safe.INDEX_TYPE_CATEGORY_OFFSET];
      }
    } else {
      return (
        high == index[Safe.INDEX_TYPE_CATEGORY_OFFSET] &&
        low == index[Safe.INDEX_TYPE_METADATA_OFFSET]
      );
    }
  }

  public boolean matches(short type, byte[] keyPrefix) {
    return (
      matches(type) &&
      (keyPrefix == null ||
        keyPrefix.length == 0 ||
        (key != null &&
          keyPrefix.length <= key.length &&
          Util.arrayCompare(key, (short) 0, keyPrefix, (short) 0, (short) keyPrefix.length) == 0))
    );
  }

  public byte[] getIndex() {
    safe.assertAccess();
    return Utils.duplicateAsTransientReset(index);
  }

  public short getIndex(byte[] dest, short offset) {
    safe.assertAccess();
    short length = (short) index.length;
    Util.arrayCopyNonAtomic(index, (short) 0, dest, offset, length);
    return length;
  }

  public byte[] getKey() {
    safe.assertAccess();
    return key != null ? Utils.duplicateAsTransientReset(key) : null;
  }

  public short getKey(byte[] dest, short offset) {
    safe.assertAccess();

    if (key == null) {
      return -1;
    }

    short length = (short) key.length;
    Util.arrayCopyNonAtomic(key, (short) 0, dest, offset, length);
    return length;
  }

  public byte[] getAlias() {
    safe.assertAccess();
    return this.alias != null ? Utils.duplicateAsTransientReset(this.alias) : null;
  }

  public short getAlias(byte[] dest, short offset) {
    safe.assertAccess();

    if (this.alias == null) {
      return -1;
    }

    short length = (short) this.alias.length;
    Util.arrayCopyNonAtomic(this.alias, (short) 0, dest, offset, length);
    return length;
  }

  public SafeDataSource getData() {
    safe.assertAccess();
    return new SafeStoredData(safe, data);
  }

  public boolean isSecret() {
    safe.assertAccess();

    if (this.secret != Constants.SAFE_TRUE && this.secret != Constants.SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    return this.secret == Constants.SAFE_TRUE;
  }

  public void setAlias(byte[] alias) {
    safe.assertAccess();

    if (alias != null) {
      safe.checkStorage((short) alias.length);
      alias = Utils.duplicateAsPersistent(alias);
    }

    this.alias = alias;
  }

  public void setData(SafeDataSource data) {
    safe.assertAccess();
    short length = data.getLength();
    safe.assertAccess();
    safe.checkStorage(length);
    byte[] replacement = Utils.duplicateAsPersistent(data, length);
    safe.assertAccess();
    this.data = replacement;
  }

  public void setData(SafeDataSource data, boolean secret) {
    safe.assertAccess();
    short length = data.getLength();
    safe.assertAccess();
    safe.checkStorage(length);
    byte[] replacement = Utils.duplicateAsPersistent(data, length);
    safe.assertAccess();

    JCSystem.beginTransaction();

    try {
      this.data = replacement;
      this.secret = secret ? Constants.SAFE_TRUE : Constants.SAFE_FALSE;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }
  }

  public void setSecret(boolean secret) {
    safe.assertAccess();

    if (!secret && this.secret != Constants.SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    this.secret = secret ? Constants.SAFE_TRUE : Constants.SAFE_FALSE;
  }

  public SafeDataSource exportData(byte[] recipientPublicKey) {
    return safe.exportItem(this, recipientPublicKey);
  }

  public void remove() {
    safe.assertAccess();
    safe.remove(this);
  }
}
