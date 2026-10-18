package monoidsafe;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class SafeSessionItemIterator implements SafeItemIteratorShareable {

  private final SafeSession session;
  private final SafeItem[] items;
  private final short length;
  private final short type;
  private final byte[] keyPrefix;
  private final short count;
  private final short maxMetadataLength;

  // SIO calls run with the client selected, so Safe-owned state must use CLEAR_ON_RESET.
  private final short[] position = JCSystem.makeTransientShortArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );

  public SafeSessionItemIterator(
    SafeSession session,
    SafeItem[] items,
    short length,
    short type,
    byte[] keyPrefix
  ) {
    this.session = session;
    this.items = items;
    this.length = length;
    this.type = type;

    // A global argument cannot be retained in the iterator.
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

        short metadataLength = SafeShareable.INDEX_LENGTH;

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

  @Override
  public short getCount() {
    session.assertAccess();
    return count;
  }

  @Override
  public short getMaxMetadataLength() {
    session.assertAccess();
    return maxMetadataLength;
  }

  @Override
  public SafeItemShareable next() {
    session.assertAccess();

    while (position[0] < length) {
      SafeItem item = items[position[0]++];

      if (item.matches(type, keyPrefix)) {
        return new SafeSessionItem(session, item);
      }
    }

    return null;
  }
}
