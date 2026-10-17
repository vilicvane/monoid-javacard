package monoidsafe;

import javacard.framework.Shareable;

public interface SafeItemShareable extends Shareable {
  byte[] getIndex();

  byte[] getKey();
  byte[] getAlias();
  byte[] getData();
  boolean isSecret();

  void setAlias(byte[] alias);
  void setData(byte[] data);
  void setData(byte[] data, boolean secret);
  void setSecret(boolean secret);

  byte[] exportData(byte[] recipientPublicKey);

  void remove();
}
