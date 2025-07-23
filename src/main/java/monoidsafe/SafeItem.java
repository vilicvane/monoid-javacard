package monoidsafe;

import javacard.framework.Util;

public class SafeItem implements SafeItemShareable {

  public byte[] index;
  public byte[] alias;
  public byte[] data;

  private MonoidSafeApplet applet;

  public SafeItem(byte[] index, byte[] alias, byte[] data, MonoidSafeApplet applet) {
    this.index = index;
    this.alias = alias;
    this.data = data;
    this.applet = applet;
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

  @Override
  public byte[] getIndex() {
    applet.assertAccess();
    return Utils.duplicateAsGlobal(index);
  }

  @Override
  public byte[] getAlias() {
    applet.assertAccess();
    return alias != null ? Utils.duplicateAsGlobal(alias) : null;
  }

  @Override
  public byte[] getData() {
    applet.assertAccess();
    return Utils.duplicateAsGlobal(data);
  }

  @Override
  public void setAlias(byte[] alias) {
    applet.assertAccess();
    this.alias = alias != null ? Utils.duplicateAsPersistent(alias) : null;
  }

  @Override
  public void setData(byte[] data) {
    applet.assertAccess();
    this.data = Utils.duplicateAsPersistent(data);
  }

  @Override
  public void remove() {
    applet.assertAccess();
    applet.remove(this);
  }
}
