package monoidsafe;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public class SafeSessionItem implements SafeItemShareable {

  private final SafeSession session;
  private final SafeItem item;

  public SafeSessionItem(SafeSession session, SafeItem item) {
    this.session = session;
    this.item = item;
  }

  @Override
  public byte[] getIndex() {
    session.assertAccess();
    return Utils.duplicateAsGlobal(item.index);
  }

  @Override
  public byte[] getKey() {
    session.assertAccess();
    return item.key != null ? Utils.duplicateAsGlobal(item.key) : null;
  }

  @Override
  public byte[] getAlias() {
    session.assertAccess();
    return item.alias != null ? Utils.duplicateAsGlobal(item.alias) : null;
  }

  @Override
  public byte[] getData() {
    session.assertAccess();
    return Utils.duplicateAsGlobal(item.data);
  }

  @Override
  public boolean isSecret() {
    session.assertAccess();

    if (item.secret != Constants.SAFE_TRUE && item.secret != Constants.SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    return item.secret == Constants.SAFE_TRUE;
  }

  @Override
  public void setAlias(byte[] alias) {
    session.assertAccess();
    item.alias = alias != null ? Utils.duplicateAsPersistent(alias) : null;
  }

  @Override
  public void setData(byte[] data) {
    session.assertAccess();
    item.data = Utils.duplicateAsPersistent(data);
  }

  @Override
  public void setData(byte[] data, boolean secret) {
    session.assertAccess();
    byte[] replacement = Utils.duplicateAsPersistent(data);

    JCSystem.beginTransaction();

    try {
      item.data = replacement;
      item.secret = secret ? Constants.SAFE_TRUE : Constants.SAFE_FALSE;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }
  }

  @Override
  public void setSecret(boolean secret) {
    session.assertAccess();

    if (!secret && item.secret != Constants.SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    item.secret = secret ? Constants.SAFE_TRUE : Constants.SAFE_FALSE;
  }

  @Override
  public byte[] exportData(byte[] recipientPublicKey) {
    return session.exportItem(item, recipientPublicKey);
  }

  @Override
  public void remove() {
    session.assertAccess();
    session.remove(item);
  }
}
