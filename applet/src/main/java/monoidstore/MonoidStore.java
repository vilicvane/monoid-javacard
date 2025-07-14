package monoidstore;

import javacard.framework.*;

public interface MonoidStore extends Shareable {
  public void verifyPIN(byte[] buffer, short offset, byte length);

  public void updatePIN(byte[] buffer, short offset, byte length);

  public boolean exists(byte[] buffer, short offset, byte indexLength);

  public short get(byte[] buffer, short offset, byte indexLength);

  public void set(byte[] buffer, short offset, byte indexLength, short length);

  public void delete(byte[] buffer, short offset, byte indexLength);
}
