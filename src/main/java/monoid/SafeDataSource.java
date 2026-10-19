package monoid;

/** A stable, read-only data range for the current operation. */
public interface SafeDataSource {
  short getLength();

  /** Copies the exact range into the supplied buffer without retaining it; ranges may be reread. */
  void read(short dataOffset, byte[] buffer, short offset, short length);
}
