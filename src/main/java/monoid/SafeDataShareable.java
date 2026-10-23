package monoid;

import javacard.framework.Shareable;

/** Range-readable data that remains stable for the operation, without exposing a private array. */
public interface SafeDataShareable extends Shareable {
  short getLength();

  /** Copies exactly the requested range into a global buffer without retaining that buffer. */
  void read(short dataOffset, byte[] buffer, short bufferOffset, short length);
}
