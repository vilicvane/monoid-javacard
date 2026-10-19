package monoididentity;

import javacard.framework.Shareable;

/** Read-only communication data copied across applet contexts in bounded global buffers. */
public interface CommunicationDataShareable extends Shareable {
  public short getLength();

  public void read(short dataOffset, byte[] buffer, short offset, short length);
}
