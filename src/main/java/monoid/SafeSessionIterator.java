package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import monoidlib.Utils;

final class SafeSessionIterator implements SafeItemIteratorShareable {

  private final MonoidSession session;
  private final SafeItemIterator iterator;
  private final Object revision;

  SafeSessionIterator(MonoidSession session, SafeItemIterator iterator, Object revision) {
    this.session = session;
    this.iterator = iterator;
    this.revision = revision;
  }

  @Override
  public short getCount() {
    session.begin();

    try {
      session.assertItemsRevision(revision);
      return iterator.getCount();
    } finally {
      session.end();
    }
  }

  @Override
  public SafeItemShareable next() {
    session.begin();

    try {
      session.assertItemsRevision(revision);
      SafeItem item = iterator.next();
      return item == null ? null : new SafeSessionItem(session, item, revision);
    } finally {
      session.end();
    }
  }

  @Override
  public short nextData(
    byte[] expectedMetadata,
    byte[] indexDest,
    short indexOffset,
    byte[] dest,
    short offset,
    short capacity
  ) {
    return nextData(
      expectedMetadata,
      (short) 0,
      expectedMetadata == null ? 0 : (short) expectedMetadata.length,
      indexDest,
      indexOffset,
      dest,
      offset,
      capacity
    );
  }

  @Override
  public short nextData(
    byte[] expectedMetadata,
    short metadataOffset,
    short metadataLength,
    byte[] indexDest,
    short indexOffset,
    byte[] dest,
    short offset,
    short capacity
  ) {
    session.begin();

    try {
      session.assertItemsRevision(revision);
      MonoidSession.assertMetadataRange(expectedMetadata, metadataOffset, metadataLength);
      MonoidSession.assertRange(indexDest, indexOffset, Safe.INDEX_LENGTH);
      MonoidSession.assertRange(dest, offset, capacity);
      SafeItem item = iterator.next();

      if (item == null) {
        return -1;
      }

      byte[] data = session.requireReadableData(item);

      if (!MonoidSession.matchesMetadata(item, expectedMetadata, metadataOffset, metadataLength)) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }

      short copied = Utils.min(capacity, (short) data.length);

      if (
        indexDest == dest &&
        copied > 0 &&
        indexOffset < (short) (offset + copied) &&
        offset < (short) (indexOffset + Safe.INDEX_LENGTH)
      ) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      Util.arrayCopyNonAtomic(item.index, (short) 0, indexDest, indexOffset, Safe.INDEX_LENGTH);
      Util.arrayCopyNonAtomic(data, (short) 0, dest, offset, copied);
      return (short) data.length;
    } finally {
      session.end();
    }
  }
}
