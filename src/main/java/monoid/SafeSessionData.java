package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

final class SafeSessionData implements SafeDataShareable {

  private final Safe owner;
  private final Object[] session = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );
  private final SafeItem item;
  private final byte[] data;
  private Object revision;

  SafeSessionData(MonoidSession session, SafeItem item, byte[] data, Object revision) {
    this.owner = session.getSafe();
    this.session[0] = session;
    this.item = item;
    this.data = data;
    this.revision = revision;
  }

  @Override
  public short getLength() {
    MonoidSession authorized = begin();

    try {
      return (short) data.length;
    } finally {
      authorized.end();
    }
  }

  @Override
  public void read(short dataOffset, byte[] buffer, short bufferOffset, short length) {
    MonoidSession authorized = begin();

    try {
      MonoidSession.assertRange(data, dataOffset, length);
      MonoidSession.assertRange(buffer, bufferOffset, length);
      Util.arrayCopyNonAtomic(data, dataOffset, buffer, bufferOffset, length);
    } finally {
      authorized.end();
    }
  }

  boolean isCurrent(MonoidSession current) {
    if (current.getSafe() != owner) {
      return false;
    }

    assertCurrentData(current);
    return true;
  }

  private MonoidSession begin() {
    MonoidSession authorized = (MonoidSession) session[0];
    if (authorized == null) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    authorized.begin();

    try {
      assertCurrentData(authorized);
      return authorized;
    } catch (RuntimeException exception) {
      authorized.end();
      throw exception;
    }
  }

  private void assertCurrentData(MonoidSession authorized) {
    Object current = authorized.requireItemRevision(item, false, revision);

    if (item.getSecretValue() != Constants.SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (item.getStoredData() != data) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    if (revision != current) {
      revision = current;
    }
  }
}
