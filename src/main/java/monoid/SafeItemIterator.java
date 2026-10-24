package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class SafeItemIterator {

  private final Safe safe;
  private final SafeItem[] items;
  private final short length;
  private final short type;
  private final byte[] metadataPrefix;
  private final short count;
  private final short maxMetadataLength;
  private final AppletGrant grant;

  // Keep iteration state usable when Monoid is called by another applet.
  private final short[] position = JCSystem.makeTransientShortArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );

  public SafeItemIterator(
    Safe safe,
    SafeItem[] items,
    short length,
    short type,
    byte[] metadataPrefix
  ) {
    this(safe, items, length, type, metadataPrefix, null);
  }

  SafeItemIterator(
    Safe safe,
    SafeItem[] items,
    short length,
    short type,
    byte[] metadataPrefix,
    AppletGrant grant
  ) {
    this.safe = safe;
    this.items = items;
    this.length = length;
    this.type = type;
    this.grant = grant;

    // Snapshot the filter for the duration of this enumeration.
    this.metadataPrefix = metadataPrefix != null && metadataPrefix.length > 0
      ? new byte[metadataPrefix.length]
      : null;

    if (this.metadataPrefix != null) {
      Util.arrayCopyNonAtomic(
        metadataPrefix,
        (short) 0,
        this.metadataPrefix,
        (short) 0,
        (short) metadataPrefix.length
      );
    }

    short count = 0;
    short maxMetadataLength = 0;

    for (short index = 0; index < length; index++) {
      SafeItem item = items[index];

      if (matches(item)) {
        count++;

        short metadataLength = Safe.INDEX_LENGTH;

        if (item.metadata != null) {
          metadataLength += (short) item.metadata.length;
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
      item.matches(type, metadataPrefix) &&
      (grant == null || grant.allows(Util.getShort(item.index, Safe.INDEX_TYPE_OFFSET), false))
    );
  }
}
