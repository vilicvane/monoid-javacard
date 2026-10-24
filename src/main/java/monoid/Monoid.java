package monoid;

import javacard.framework.Shareable;

/**
 * Caller-bound access to the current applet grant. Sessions and returned handles expire on card
 * reset, Monoid Reset, grant replacement or revocation. An expired session cannot be
 * reauthenticated. SIO parameter 0 creates an independent session; parameter 1 may reuse the
 * caller's current session and clears its authentication on every acquisition. Authenticate
 * again before use, including when parameter 1 returns the same object. Array arguments must
 * be global arrays.
 */
public interface Monoid extends Shareable {
  byte HMAC_SHA1 = 1;
  byte HMAC_SHA256 = 2;
  byte HMAC_SHA512 = 3;

  /** Authenticates the caller's private 32-byte installation token, not its public hash. */
  void authenticate(byte[] token);

  /** Authenticates exactly 32 bytes at offset; does not retain the input buffer. */
  void authenticate(byte[] token, short offset);

  /** Consumes this current grant's one pending user authentication; fails when absent. */
  void consumeUserAuthentication();

  /** Revokes this grant's pending user authentication, without affecting any other grant. */
  void revokeUserAuthentication();

  /**
   * Uses a built-in HMAC key explicitly authorized by its index in the current keys grant.
   * Writes 20, 32 or 64 bytes. Inputs may overlap output. Does not consume user authentication.
   */
  short hmac(
    byte algorithm,
    byte[] index,
    short indexOffset,
    byte[] message,
    short messageOffset,
    short messageLength,
    byte[] dest,
    short destOffset
  );

  /**
   * Uses the granted seed with context "monoid applet: " || u16be(domain.length) || domain ||
   * context. Writes a 65-byte uncompressed P-256 public key; returns 65.
   */
  short getMonoid001PublicKey(byte[] context, byte[] dest, short offset);

  /** Uses the specified context slice; input and output ranges may overlap. */
  short getMonoid001PublicKey(
    byte[] context,
    short contextOffset,
    short contextLength,
    byte[] dest,
    short offset
  );

  /** Signs a 32-byte digest with the same derived key. Writes 64-byte r || s; returns 64. */
  short signMonoid001ECDSADigest(byte[] context, byte[] digest, byte[] dest, short offset);

  /** Uses a context slice and exactly 32 digest bytes; input and output ranges may overlap. */
  short signMonoid001ECDSADigest(
    byte[] context,
    short contextOffset,
    short contextLength,
    byte[] digest,
    short digestOffset,
    byte[] dest,
    short offset
  );

  /** Applies the existing Type/category filter within the exact Types granted to this caller. */
  SafeItemIteratorShareable list(short type);

  /** Additionally filters by metadata prefix; null or empty means no prefix filter. */
  SafeItemIteratorShareable list(short type, byte[] metadataPrefix);

  /**
   * Returns the total matching count and copies the first min(count, capacity) 10-byte indices.
   * Capacity is an index count, not a byte count. Uses the same Type/grant and prefix filters as
   * list(); null or empty prefix means no filter. A null prefix requires zero offset/length.
   * The prefix slice and destination range must not overlap. No snapshot is retained.
   */
  short listIndices(
    short type,
    byte[] metadataPrefix,
    short metadataOffset,
    short metadataLength,
    byte[] dest,
    short offset,
    short capacity
  );

  /** Requires permission for the index's Type; returns null when the item is absent. */
  SafeItemShareable get(byte[] index);

  /**
   * Returns a readable data snapshot for a 10-byte index and exact metadata slice; null matches
   * only null item metadata and requires zero offset/length. Returns null if absent or mismatched.
   * The snapshot checks current authorization, item identity and data identity on every use.
   * Input arrays are not retained.
   */
  SafeDataShareable getData(
    byte[] index,
    short indexOffset,
    byte[] expectedMetadata,
    short metadataOffset,
    short metadataLength
  );

  /**
   * Checks a snapshot from this Safe against this session's current authorization and data.
   * Returns false for foreign, removed, replaced or changed data; authorization errors still
   * throw. This check does not revive the snapshot's original session after reset or revocation.
   */
  boolean isDataCurrent(SafeDataShareable data);

  /**
   * Copies min(capacity, data length) bytes of a readable item and returns its total data length.
   * Returns -1 when absent or when its metadata differs from expectedMetadata; null matches only null.
   * This call does not retain a snapshot for later reads. Use get() for data larger than dest.
   */
  short readData(byte[] index, byte[] expectedMetadata, byte[] dest, short offset, short capacity);

  /**
   * Reads a 10-byte index and exact metadata slice. Null metadata requires zero offset/length.
   * Input slices are consumed before copying data, so they may overlap the output range.
   */
  short readData(
    byte[] index,
    short indexOffset,
    byte[] expectedMetadata,
    short metadataOffset,
    short metadataLength,
    byte[] dest,
    short offset,
    short capacity
  );

  /** Requires a writable Type grant. Copies all inputs; metadata and alias may be null. */
  SafeItemShareable create(
    byte[] index,
    byte[] metadata,
    byte[] alias,
    SafeDataShareable data,
    boolean secret
  );

  /**
   * Requires a writable Type grant. Copies a 10-byte index, metadata slice and complete data slice
   * without a client callback. Known Types retain create()'s data and digest-index validation.
   * Metadata and alias may be null; null metadata requires zero offset/length. Inputs may overlap.
   * Returns false when the index already exists, without changing that item.
   */
  boolean createData(
    byte[] index,
    short indexOffset,
    byte[] metadata,
    short metadataOffset,
    short metadataLength,
    byte[] alias,
    byte[] data,
    short dataOffset,
    short dataLength,
    boolean secret
  );

  /** Atomically removes this exact Type; requires writable permission even when no items exist. */
  void removeAll(short type);
}
