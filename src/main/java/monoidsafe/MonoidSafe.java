package monoidsafe;

import javacard.framework.Shareable;

public interface MonoidSafe extends Shareable {
  public static final byte INDEX_DIGEST_LENGTH = 8;
  public static final byte INDEX_LENGTH = 1 + INDEX_DIGEST_LENGTH;

  public boolean isPINSet();

  public byte getPINTriesRemaining();

  public boolean checkPIN(byte[] buffer, short offset, byte length);

  public void updatePIN(byte[] buffer, short offset, byte length);

  public boolean isPINValidated();

  public byte[] list(byte type);

  public byte[] get(byte[] buffer, short offset);

  public boolean set(byte[] buffer, short offset, short length);

  public boolean clear(byte[] buffer, short offset);
}
