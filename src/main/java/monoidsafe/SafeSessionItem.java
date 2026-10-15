package monoidsafe;

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
  public void remove() {
    session.assertAccess();
    session.remove(item);
  }
}
