package monoid;

import javacard.framework.Shareable;

public interface MonoidClientShareable extends Shareable {
  /** Copies SHA-256 of the client's private 32-byte installation token into a global array. */
  short getTokenHash(byte[] dest, short offset);
}
