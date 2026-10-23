package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

final class SafeSessionItem implements SafeItemShareable {

  private final MonoidSession session;
  private final SafeItem item;
  private Object revision;

  SafeSessionItem(MonoidSession session, SafeItem item, Object revision) {
    this.session = session;
    this.item = item;
    this.revision = revision;
  }

  @Override
  public byte[] getIndex() {
    begin(false);

    try {
      return Utils.duplicateAsGlobal(item.index);
    } finally {
      session.end();
    }
  }

  @Override
  public byte[] getKey() {
    begin(false);

    try {
      return item.key == null ? null : Utils.duplicateAsGlobal(item.key);
    } finally {
      session.end();
    }
  }

  @Override
  public byte[] getAlias() {
    begin(false);

    try {
      return item.alias == null ? null : Utils.duplicateAsGlobal(item.alias);
    } finally {
      session.end();
    }
  }

  @Override
  public boolean isSecret() {
    begin(false);

    try {
      return item.isSecret();
    } finally {
      session.end();
    }
  }

  @Override
  public SafeDataShareable getData() {
    begin(false);

    try {
      assertReadable();
      return new SafeSessionData(session, item, item.getStoredData(), revision);
    } finally {
      session.end();
    }
  }

  @Override
  public void setAlias(byte[] alias) {
    begin(true);

    try {
      item.setAlias(alias);
    } finally {
      session.end();
    }
  }

  @Override
  public void setData(SafeDataShareable data) {
    setData(data, false, false);
  }

  @Override
  public void setData(SafeDataShareable data, boolean secret) {
    setData(data, secret, true);
  }

  private void setData(SafeDataShareable data, boolean secret, boolean setSecret) {
    begin(true);
    SafeSessionSource source = null;

    try {
      source = new SafeSessionSource(session, data);

      if (setSecret) {
        item.setData(source, secret);
      } else {
        item.setData(source);
      }
    } finally {
      if (source != null) {
        source.close();
      }

      session.end();
    }
  }

  @Override
  public void setSecret(boolean secret) {
    begin(true);

    try {
      item.setSecret(secret);
    } finally {
      session.end();
    }
  }

  @Override
  public void remove() {
    begin(true);

    try {
      item.remove();
    } finally {
      session.end();
    }
  }

  private void begin(boolean write) {
    session.begin();

    try {
      Object current = session.requireItemRevision(item, write, revision);

      if (revision != current) {
        revision = current;
      }
    } catch (RuntimeException exception) {
      session.end();
      throw exception;
    }
  }

  private void assertReadable() {
    if (item.getSecretValue() != Constants.SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }
}
