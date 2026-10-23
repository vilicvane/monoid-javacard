package monoid;

import javacard.framework.JCSystem;
import monoidlib.Utils;

public abstract class KeyDerivation {

  private static final short CACHE_SIZE = 32;

  private static CacheEntry[] cache;
  private static short nextCacheIndex;
  private static short[] recentCacheIndex;

  public static void init() {
    cache = new CacheEntry[CACHE_SIZE];
    nextCacheIndex = 0;
    recentCacheIndex = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
  }

  public static void dispose() {
    cache = null;
    nextCacheIndex = 0;
    recentCacheIndex = null;
  }

  public static void clearCache() {
    for (short i = 0; i < CACHE_SIZE; i++) {
      cache[i] = null;
    }

    nextCacheIndex = 0;
    recentCacheIndex[0] = 0;
  }

  public final DerivedKey derive(byte[] master, byte[] input) {
    return derive(master, input, false);
  }

  public final DerivedKey deriveFromSeed(byte[] seed, byte[] input) {
    return derive(seed, input, true);
  }

  private DerivedKey derive(byte[] source, byte[] input, boolean fromSeed) {
    // A public-key check is commonly followed by signing the same input. The hint avoids
    // scanning the full cache, but never replaces its complete key comparison or FIFO order.
    CacheEntry recent = cache[recentCacheIndex[0]];
    if (
      recent != null &&
      recent.owner == this &&
      recent.fromSeed == fromSeed &&
      Utils.isEqual(recent.source, source) &&
      Utils.isEqual(recent.input, input)
    ) {
      return recent.result;
    }

    CacheEntry matchingSource = null;

    for (short i = 0; i < CACHE_SIZE; i++) {
      CacheEntry cached = cache[i];

      if (
        cached != null &&
        cached.owner == this &&
        cached.fromSeed == fromSeed &&
        Utils.isEqual(cached.source, source)
      ) {
        if (Utils.isEqual(cached.input, input)) {
          recentCacheIndex[0] = i;
          return cached.result;
        }
        if (fromSeed) {
          matchingSource = cached;
        }
      }
    }

    // Only existing result entries retain a seed's immutable master. No separate cache or
    // FIFO slot is needed; clearing/evicting the last related result also releases its master.
    byte[] master = fromSeed
      ? matchingSource == null ? deriveMasterFromSeed(source) : matchingSource.master
      : source;
    DerivedKey result = new DerivedKey(deriveKey(master, input));
    byte[] storedSource = matchingSource == null
      ? Utils.duplicateAsPersistent(source)
      : matchingSource.source;
    CacheEntry entry = new CacheEntry(
      this,
      storedSource,
      fromSeed,
      input,
      result,
      fromSeed ? master : null
    );

    // Publish the completed entry and advance FIFO together; hits do not write to storage.
    JCSystem.beginTransaction();

    try {
      cache[nextCacheIndex] = entry;
      recentCacheIndex[0] = nextCacheIndex;
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

    if (JCSystem.isObjectDeletionSupported()) {
      JCSystem.requestObjectDeletion();
    }

    return result;
  }

  protected abstract byte[] getMasterKeyLabel();

  protected byte[] deriveMasterFromSeed(byte[] seed) {
    if (seed.length != Keystore.SEED_512_LENGTH) {
      KeystoreException.throwIt(KeystoreException.REASON_UNSUPPORTED_SEED_LENGTH);
      return null;
    }

    return LibHMACSha512.digest(getMasterKeyLabel(), seed);
  }

  /** Treat master as immutable; seed-derived calls can share its private cached bytes. */
  protected abstract byte[] deriveKey(byte[] master, byte[] input);

  private static final class CacheEntry {

    private final KeyDerivation owner;
    private final byte[] source;
    private final boolean fromSeed;
    private final byte[] input;
    private final DerivedKey result;
    private final byte[] master;

    private CacheEntry(
      KeyDerivation owner,
      byte[] source,
      boolean fromSeed,
      byte[] input,
      DerivedKey result,
      byte[] master
    ) {
      this.owner = owner;
      this.source = source;
      this.fromSeed = fromSeed;
      this.input = Utils.duplicateAsPersistent(input);
      this.result = result;
      this.master = master;
    }
  }
}
