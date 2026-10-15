package monoidsafe;

import javacard.framework.Shareable;

/**
 * A Safe session bound to its caller. Data access requires this session to verify
 * the Safe PIN. Repeated acquisition reuses the caller's authorized session.
 * Checking the PIN revokes only this caller's previous authorization. Other
 * callers retain their own authorization.
 * Updating the PIN, exhausting its shared try counter, or a card reset revokes
 * all sessions. Item interfaces belong to the session that returned them.
 */
public interface SafeShareable extends Shareable {
  public static final byte INDEX_TYPE_OFFSET = 0;
  public static final byte INDEX_TYPE_LENGTH = 2;
  public static final byte INDEX_TYPE_CATEGORY_OFFSET = 0;
  public static final byte INDEX_TYPE_METADATA_OFFSET = INDEX_TYPE_CATEGORY_OFFSET + 1;

  public static final byte INDEX_ID_OFFSET = INDEX_TYPE_OFFSET + INDEX_TYPE_LENGTH;
  public static final byte INDEX_ID_LENGTH = 8;

  public static final byte INDEX_LENGTH = INDEX_TYPE_LENGTH + INDEX_ID_LENGTH;

  public byte[] getId();

  public boolean isPINSet();

  public byte getPINTriesRemaining();

  public boolean checkPIN(byte[] buffer, short offset, byte length);

  /** Requires authorization except when setting the Safe PIN for the first time. */
  public void updatePIN(byte[] buffer, short offset, byte length);

  /** Reports authorization for this session and its current caller. */
  public boolean isPINValidated();

  /**
   * List items of a specific type.
   * @param type The type of items to list, if the lower byte (metadata) is 0,
   * it will filter by the higher byte (category), otherwise it will filter by
   * both.
   * @return An array of SafeItemShareable objects that match the type.
   */
  public Object[] list(short type);

  /**
   * List items matching the type filter and a prefix of their data.
   * @param dataPrefix A byte prefix; null or empty matches any data.
   * @see #list(short)
   */
  public Object[] list(short type, byte[] dataPrefix);

  public SafeItemShareable get(byte[] index);

  public SafeItemShareable create(byte[] index, byte[] alias, byte[] data);
}
