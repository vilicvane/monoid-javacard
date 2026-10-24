package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import monoidlib.Utils;

public class SafeItem {

  private final Safe safe;

  public byte[] index;
  public byte[] metadata;
  public byte[] alias;

  private ItemState state;

  private static final class ItemState {

    private final byte[] data;
    private final short secret;

    ItemState(byte[] data, short secret) {
      if (secret != Constants.SAFE_TRUE && secret != Constants.SAFE_FALSE) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      this.data = data;
      this.secret = secret;
    }
  }

  SafeItem(Safe safe, byte[] index, byte[] metadata, byte[] alias, byte[] data, short secret) {
    this.safe = safe;
    this.index = index;
    this.metadata = metadata;
    this.alias = alias;
    this.state = new ItemState(data, secret);
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

  public boolean matches(short type, byte[] metadataPrefix) {
    return (
      matches(type) &&
      (metadataPrefix == null ||
        metadataPrefix.length == 0 ||
        (metadata != null &&
          metadataPrefix.length <= metadata.length &&
          Util.arrayCompare(
            metadata,
            (short) 0,
            metadataPrefix,
            (short) 0,
            (short) metadataPrefix.length
          ) ==
          0))
    );
  }

  public byte[] getIndex() {
    safe.assertAccess();
    return Utils.duplicateAsPersistent(index);
  }

  public short getIndex(byte[] dest, short offset) {
    safe.assertAccess();
    short length = (short) index.length;
    Util.arrayCopyNonAtomic(index, (short) 0, dest, offset, length);
    return length;
  }

  public byte[] getMetadata() {
    safe.assertAccess();
    return metadata != null ? Utils.duplicateAsPersistent(metadata) : null;
  }

  public short getMetadata(byte[] dest, short offset) {
    safe.assertAccess();

    if (metadata == null) {
      return -1;
    }

    short length = (short) metadata.length;
    Util.arrayCopyNonAtomic(metadata, (short) 0, dest, offset, length);
    return length;
  }

  public byte[] getAlias() {
    safe.assertAccess();
    return this.alias != null ? Utils.duplicateAsPersistent(this.alias) : null;
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
    return new SafeStoredData(safe, state.data);
  }

  public boolean isSecret() {
    safe.assertAccess();
    short secret = state.secret;

    if (secret != Constants.SAFE_TRUE && secret != Constants.SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    return secret == Constants.SAFE_TRUE;
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
    byte[] replacement = data.duplicateAsPersistent(length);
    safe.assertAccess();
    publish(replacement, state.secret);
  }

  public void setData(SafeDataSource data, boolean secret) {
    safe.assertAccess();
    short length = data.getLength();
    safe.assertAccess();
    safe.checkStorage(length);
    byte[] replacement = data.duplicateAsPersistent(length);
    safe.assertAccess();
    publish(replacement, secret ? Constants.SAFE_TRUE : Constants.SAFE_FALSE);
  }

  public void setSecret(boolean secret) {
    safe.assertAccess();
    short current = state.secret;

    if (!secret) {
      if (current == Constants.SAFE_FALSE) {
        return;
      }

      if (current != Constants.SAFE_TRUE) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    publish(state.data, Constants.SAFE_TRUE);
  }

  public SafeDataSource exportData(byte[] recipientPublicKey) {
    return safe.exportItem(this, recipientPublicKey);
  }

  public void remove() {
    safe.assertAccess();
    safe.remove(this);
  }

  byte[] getStoredData() {
    return state.data;
  }

  short getSecretValue() {
    return state.secret;
  }

  private void publish(byte[] data, short secret) {
    ItemState replacement = new ItemState(data, secret);
    boolean transaction = JCSystem.getTransactionDepth() == 0;

    if (transaction) {
      JCSystem.beginTransaction();
    }

    try {
      state = replacement;
      if (transaction) {
        JCSystem.commitTransaction();
      }
    } finally {
      if (transaction && JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }
  }
}
