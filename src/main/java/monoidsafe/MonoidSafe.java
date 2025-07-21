package monoidsafe;

import javacard.framework.Shareable;

public interface MonoidSafe extends Shareable {
  public static final byte INDEX_OFFSET = 0;

  public static final byte INDEX_TYPE_OFFSET = INDEX_OFFSET;
  public static final byte INDEX_TYPE_CATEGORY_OFFSET = INDEX_TYPE_OFFSET;
  public static final byte INDEX_TYPE_METADATA_OFFSET = INDEX_TYPE_CATEGORY_OFFSET + 1;
  public static final byte INDEX_TYPE_LENGTH = 2;

  public static final byte INDEX_ID_OFFSET = INDEX_TYPE_OFFSET + INDEX_TYPE_LENGTH;
  public static final byte INDEX_ID_LENGTH = 8;

  public static final byte INDEX_LENGTH = INDEX_TYPE_LENGTH + INDEX_ID_LENGTH;

  public static final byte DATA_OFFSET = INDEX_OFFSET + INDEX_LENGTH;

  public boolean isPINSet();

  public byte getPINTriesRemaining();

  public boolean checkPIN(byte[] buffer, short offset, byte length);

  public void updatePIN(byte[] buffer, short offset, byte length);

  public boolean isPINValidated();

  public byte[] list(short type);

  public byte[] get(byte[] buffer, short offset);

  public boolean set(byte[] buffer, short offset, short length);

  public boolean remove(byte[] buffer, short offset);
}
