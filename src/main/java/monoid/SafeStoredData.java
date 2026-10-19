package monoid;

import javacard.framework.Util;

public class SafeStoredData implements SafeDataSource {

  private final Safe safe;
  private final byte[] data;

  public SafeStoredData(Safe safe, byte[] data) {
    this.safe = safe;
    this.data = data;
  }

  @Override
  public short getLength() {
    safe.assertAccess();
    return (short) data.length;
  }

  @Override
  public void read(short dataOffset, byte[] buffer, short offset, short length) {
    safe.assertAccess();
    Util.arrayCopyNonAtomic(data, dataOffset, buffer, offset, length);
  }
}
