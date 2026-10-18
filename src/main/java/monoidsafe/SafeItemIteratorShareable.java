package monoidsafe;

import javacard.framework.Shareable;

/** Enumerates items during one operation, without modifying the Safe or resetting the card. */
public interface SafeItemIteratorShareable extends Shareable {
  short getCount();

  /** Maximum combined index, key and alias length among matching items. */
  short getMaxMetadataLength();

  /** Returns the next matching item, or null when exhausted. */
  SafeItemShareable next();
}
