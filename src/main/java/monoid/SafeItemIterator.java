package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class SafeItemIterator {

  private final Safe safe;
  private final SafeItem[] items;
  private final short length;
  private final short type;
  private final byte[] keyPrefix;
  private final short count;
  private final short maxMetadataLength;
  private final AppletGrant grant;

  // Keep iteration state usable when Monoid is called by another applet.
  private final short[] position = JCSystem.makeTransientShortArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );

  public SafeItemIterator(Safe safe, SafeItem[] items, short length, short type, byte[] keyPrefix) {
    this(safe, items, length, type, keyPrefix, null);
  }

  SafeItemIterator(
    Safe safe,
    SafeItem[] items,
    short length,
    short type,
    byte[] keyPrefix,
    AppletGrant grant
  ) {
    this.safe = safe;
    this.items = items;
    this.length = length;
    this.type = type;
    this.grant = grant;

    // Snapshot the filter for the duration of this enumeration.
    this.keyPrefix = keyPrefix != null && keyPrefix.length > 0 ? new byte[keyPrefix.length] : null;

    if (this.keyPrefix != null) {
      Util.arrayCopyNonAtomic(
        keyPrefix,
        (short) 0,
        this.keyPrefix,
        (short) 0,
        (short) keyPrefix.length
      );
    }

    short count = 0;
    short maxMetadataLength = 0;

    for (short index = 0; index < length; index++) {
      SafeItem item = items[index];

      if (matches(item)) {
        count++;

        short metadataLength = Safe.INDEX_LENGTH;

        if (item.key != null) {
          metadataLength += (short) item.key.length;
        }

        if (item.alias != null) {
          metadataLength += (short) item.alias.length;
        }

        if (metadataLength > maxMetadataLength) {
          maxMetadataLength = metadataLength;
        }
      }
    }

    this.count = count;
    this.maxMetadataLength = maxMetadataLength;
  }

  public short getCount() {
    safe.assertAccess();
    return count;
  }

  public short getMaxMetadataLength() {
    safe.assertAccess();
    return maxMetadataLength;
  }

  public SafeItem next() {
    safe.assertAccess();

    while (position[0] < length) {
      SafeItem item = items[position[0]++];

      if (matches(item)) {
        return item;
      }
    }

    return null;
  }

  private boolean matches(SafeItem item) {
    return (
      item.matches(type, keyPrefix) &&
      (grant == null || grant.allows(Util.getShort(item.index, Safe.INDEX_TYPE_OFFSET), false))
    );
  }
}
