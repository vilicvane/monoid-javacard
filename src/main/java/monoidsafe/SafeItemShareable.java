package monoidsafe;

import javacard.framework.Shareable;

public interface SafeItemShareable extends Shareable {
  byte[] getIndex();
  short getIndex(byte[] dest, short offset);

  byte[] getKey();
  /** Copies the key and returns its length, or -1 if absent. */
  short getKey(byte[] dest, short offset);

  byte[] getAlias();
  /** Copies the alias and returns its length, or -1 if absent. */
  short getAlias(byte[] dest, short offset);

  byte[] getData();
  boolean isSecret();

  void setAlias(byte[] alias);
  void setData(byte[] data);
  void setData(byte[] data, boolean secret);
  void setSecret(boolean secret);

  byte[] exportData(byte[] recipientPublicKey);

  void remove();
}
