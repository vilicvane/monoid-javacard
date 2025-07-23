package monoidsafe;

import javacard.framework.Shareable;

public interface SafeShareable extends Shareable {
  public static final byte INDEX_TYPE_OFFSET = 0;
  public static final byte INDEX_TYPE_LENGTH = 2;
  public static final byte INDEX_TYPE_CATEGORY_OFFSET = 0;
  public static final byte INDEX_TYPE_METADATA_OFFSET = INDEX_TYPE_CATEGORY_OFFSET + 1;

  public static final byte INDEX_ID_OFFSET = INDEX_TYPE_OFFSET + INDEX_TYPE_LENGTH;
  public static final byte INDEX_ID_LENGTH = 8;

  public static final byte INDEX_LENGTH = INDEX_TYPE_LENGTH + INDEX_ID_LENGTH;

  public boolean isPINSet();

  public byte getPINTriesRemaining();

  public boolean checkPIN(byte[] buffer, short offset, byte length);

  public void updatePIN(byte[] buffer, short offset, byte length);

  public boolean isPINValidated();

  /**
   * List items of a specific type.
   * @param type The type of items to list, if the lower byte (metadata) is 0,
   * it will filter by the higher byte (category), otherwise it will filter by
   * both.
   * @return An array of SafeItemShareable objects that match the type.
   */
  public Object[] list(short type);

  public SafeItemShareable get(byte[] index);

  public SafeItemShareable create(byte[] index, byte[] alias, byte[] data);
}
