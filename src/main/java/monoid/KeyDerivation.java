package monoid;

import javacard.framework.JCSystem;

public abstract class KeyDerivation {

  private static final short CACHE_SIZE = 32;

  private static CacheEntry[] cache;
  private static short nextCacheIndex;

  public static void init() {
    cache = new CacheEntry[CACHE_SIZE];
    nextCacheIndex = 0;
  }

  public static void dispose() {
    cache = null;
    nextCacheIndex = 0;
  }

  public final byte[] derive(byte[] master, byte[] input) {
    for (short i = 0; i < CACHE_SIZE; i++) {
      CacheEntry cached = cache[i];

      if (
        cached != null &&
        cached.owner == this &&
        Utils.isEqual(cached.master, master) &&
        Utils.isEqual(cached.input, input)
      ) {
        return Utils.duplicateAsTransientDeselect(cached.key);
      }
    }

    byte[] key = deriveKey(master, input);
    CacheEntry entry = new CacheEntry(this, master, input, key);

    // Publish the completed entry and advance FIFO together; hits do not write to storage.
    JCSystem.beginTransaction();

    try {
      cache[nextCacheIndex] = entry;
      nextCacheIndex++;

      if (nextCacheIndex == CACHE_SIZE) {
        nextCacheIndex = 0;
      }

      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }

    return key;
  }

  protected abstract byte[] deriveKey(byte[] master, byte[] input);

  private static final class CacheEntry {

    private final KeyDerivation owner;
    private final byte[] master;
    private final byte[] input;
    private final byte[] key;

    private CacheEntry(KeyDerivation owner, byte[] master, byte[] input, byte[] key) {
      this.owner = owner;
      this.master = Utils.duplicateAsPersistent(master);
      this.input = Utils.duplicateAsPersistent(input);
      this.key = Utils.duplicateAsPersistent(key);
    }
  }
}
