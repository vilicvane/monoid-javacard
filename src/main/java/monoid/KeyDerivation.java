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

  public static void clearCache() {
    for (short i = 0; i < CACHE_SIZE; i++) {
      cache[i] = null;
    }

    nextCacheIndex = 0;
  }

  public final DerivedKey derive(byte[] master, byte[] input) {
    return derive(master, input, false);
  }

  public final DerivedKey deriveFromSeed(byte[] seed, byte[] input) {
    return derive(seed, input, true);
  }

  private DerivedKey derive(byte[] source, byte[] input, boolean fromSeed) {
    for (short i = 0; i < CACHE_SIZE; i++) {
      CacheEntry cached = cache[i];

      if (
        cached != null &&
        cached.owner == this &&
        cached.fromSeed == fromSeed &&
        Utils.isEqual(cached.source, source) &&
        Utils.isEqual(cached.input, input)
      ) {
        return cached.result;
      }
    }

    byte[] master = fromSeed ? deriveMasterFromSeed(source) : source;
    DerivedKey result = new DerivedKey(deriveKey(master, input));
    CacheEntry entry = new CacheEntry(this, source, fromSeed, input, result);

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

  protected abstract byte[] deriveKey(byte[] master, byte[] input);

  private static final class CacheEntry {

    private final KeyDerivation owner;
    private final byte[] source;
    private final boolean fromSeed;
    private final byte[] input;
    private final DerivedKey result;

    private CacheEntry(
      KeyDerivation owner,
      byte[] source,
      boolean fromSeed,
      byte[] input,
      DerivedKey result
    ) {
      this.owner = owner;
      this.source = Utils.duplicateAsPersistent(source);
      this.fromSeed = fromSeed;
      this.input = Utils.duplicateAsPersistent(input);
      this.result = result;
    }
  }
}
