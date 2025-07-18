package monoidsafe;

import javacard.framework.*;

public interface MonoidSafe extends Shareable {
  public boolean isPINSet();

  public byte getPINTriesRemaining();

  public boolean checkPIN(byte[] buffer, short offset, byte length);

  public void updatePIN(byte[] buffer, short offset, byte length);

  public boolean isPINValidated();

  public boolean exists(byte[] buffer, short offset, byte indexLength);

  public byte[] get(byte[] buffer, short offset, byte indexLength);

  public void set(byte[] buffer, short offset, byte indexLength, short length);

  public void delete(byte[] buffer, short offset, byte indexLength);
}
