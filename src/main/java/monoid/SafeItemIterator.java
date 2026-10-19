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

  // Keep iteration state usable when Monoid is called by another applet.
  private final short[] position = JCSystem.makeTransientShortArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );

  public SafeItemIterator(Safe safe, SafeItem[] items, short length, short type, byte[] keyPrefix) {
    this.safe = safe;
    this.items = items;
    this.length = length;
    this.type = type;

    // Snapshot the filter for the duration of this enumeration.
    this.keyPrefix = keyPrefix != null && keyPrefix.length > 0
      ? JCSystem.makeTransientByteArray((short) keyPrefix.length, JCSystem.CLEAR_ON_RESET)
      : null;

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

      if (item.matches(type, this.keyPrefix)) {
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

      if (item.matches(type, keyPrefix)) {
        return item;
      }
    }

    return null;
  }
}
