package monoidsafe;

import javacard.framework.Util;

public class SafeSessionData implements SafeDataShareable {

  private final SafeSession session;
  private final byte[] data;

  public SafeSessionData(SafeSession session, byte[] data) {
    this.session = session;
    this.data = data;
  }

  @Override
  public short getLength() {
    session.assertAccess();
    return (short) data.length;
  }

  @Override
  public void read(short dataOffset, byte[] buffer, short offset, short length) {
    session.assertAccess();
    Util.arrayCopyNonAtomic(data, dataOffset, buffer, offset, length);
  }
}
