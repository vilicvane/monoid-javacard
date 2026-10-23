package monoid;

import monoidlib.Utils;

/** A stable, read-only data range for the current operation. */
public abstract class SafeDataSource {

  private static final short COPY_LENGTH = 256;

  public abstract short getLength();

  /** Copies the exact range into the supplied buffer without retaining it; ranges may be reread. */
  public abstract void read(short dataOffset, byte[] buffer, short offset, short length);

  public byte[] duplicateAsPersistent(short length) {
    byte[] duplicate = new byte[length];

    for (short offset = 0; offset < length; ) {
      short copied = Utils.min((short) (length - offset), COPY_LENGTH);
      read(offset, duplicate, offset, copied);
      offset += copied;
    }

    return duplicate;
  }

  public byte[] duplicateAsPersistent() {
    return duplicateAsPersistent(getLength());
  }
}
