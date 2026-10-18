package monoidsafe;

import javacard.framework.Shareable;

/** A stable, read-only data range for the current operation. */
public interface SafeDataShareable extends Shareable {
  short getLength();

  /** Copies the exact range into a global buffer without retaining it; ranges may be reread. */
  void read(short dataOffset, byte[] buffer, short offset, short length);
}
