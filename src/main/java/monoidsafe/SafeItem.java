package monoidsafe;

import javacard.framework.Util;

public class SafeItem {

  public byte[] index;
  public byte[] alias;
  public byte[] data;

  public SafeItem(byte[] index, byte[] alias, byte[] data) {
    this.index = index;
    this.alias = alias;
    this.data = data;
  }

  public boolean matches(byte[] index) {
    return (
      Util.arrayCompare(this.index, (short) 0, index, (short) 0, SafeShareable.INDEX_LENGTH) == 0
    );
  }

  public boolean matches(short type) {
    byte high = (byte) (type >> 8);
    byte low = (byte) (type & 0xFF);

    if (low == 0) {
      if (high == 0) {
        return true;
      } else {
        return high == index[SafeShareable.INDEX_TYPE_CATEGORY_OFFSET];
      }
    } else {
      return (
        high == index[SafeShareable.INDEX_TYPE_CATEGORY_OFFSET] &&
        low == index[SafeShareable.INDEX_TYPE_METADATA_OFFSET]
      );
    }
  }

  public boolean matches(short type, byte[] dataPrefix) {
    return (
      matches(type) &&
      (dataPrefix == null ||
        (dataPrefix.length <= data.length &&
          Util.arrayCompare(data, (short) 0, dataPrefix, (short) 0, (short) dataPrefix.length) ==
          0))
    );
  }
}
