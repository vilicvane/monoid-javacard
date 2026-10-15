package monoidsafe;

import javacard.framework.Shareable;

public interface SafeItemShareable extends Shareable {
  byte[] getIndex();

  byte[] getKey();
  byte[] getAlias();
  byte[] getData();

  void setAlias(byte[] alias);
  void setData(byte[] data);

  void remove();
}
