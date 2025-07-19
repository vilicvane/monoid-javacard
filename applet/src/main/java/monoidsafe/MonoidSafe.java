package monoidsafe;

import javacard.framework.*;

public interface MonoidSafe extends Shareable {
  public boolean isPINSet();

  public byte getPINTriesRemaining();

  public boolean checkPIN(byte[] buffer, short offset, byte length);

  public void updatePIN(byte[] buffer, short offset, byte length);

  public boolean isPINValidated();

  public byte[] list(byte type, byte indexLength);

  public byte[] get(byte[] buffer, short offset, byte indexLength);

  public boolean set(byte[] buffer, short offset, byte indexLength, short length);

  public boolean clear(byte[] buffer, short offset, byte indexLength);
}
