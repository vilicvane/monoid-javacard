package monoid;

import javacard.framework.Shareable;

/** Operation-local enumeration restricted to the session's live Type grants. */
public interface SafeItemIteratorShareable extends Shareable {
  /** Counts only items matching both the filter and the granted Types. */
  short getCount();

  /** Returns the next restricted item handle, or null at the end. */
  SafeItemShareable next();

  /**
   * Advances once, copies the true 10-byte index and min(capacity, data length) bytes, and returns
   * the total data length, or -1 at the end. expectedMetadata must match exactly, including null;
   * a mismatch fails with 6985, not end-of-enumeration. Output regions must not overlap. Errors
   * after advancing abort this operation; use a new enumeration rather than retrying the item.
   */
  short nextData(
    byte[] expectedMetadata,
    byte[] indexDest,
    short indexOffset,
    byte[] dest,
    short offset,
    short capacity
  );

  /** Uses an exact metadata slice, consumed before either output range is written. */
  short nextData(
    byte[] expectedMetadata,
    short metadataOffset,
    short metadataLength,
    byte[] indexDest,
    short indexOffset,
    byte[] dest,
    short offset,
    short capacity
  );
}
