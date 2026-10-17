package monoidsafeidentity;

import javacard.framework.Shareable;

/** Card-local key protection for Safe. Arguments and results cross contexts in global arrays. */
public interface SafeIdentityShareable extends Shareable {
  /** The persistent four-byte random display ID generated at Identity installation. */
  public byte[] getId();

  /** The stable P-256 public key, encoded as an uncompressed 65-byte SEC 1 point. */
  public byte[] getPublicKey();

  /**
   * Encrypts a 32-byte communication key for the recipient, authenticating this Identity.
   * Uses HPKE Auth with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM.
   * Context is HPKE info; the result is enc (65 bytes), ciphertext (32 bytes), tag (16 bytes).
   */
  public byte[] encryptCommunicationKey(byte[] recipientPublicKey, byte[] context, byte[] key);

  /**
   * Authenticates the expected sender and identical context before returning the key.
   * The sender public key must come from the caller's trust decision, not the envelope.
   */
  public byte[] decryptCommunicationKey(
    byte[] senderPublicKey,
    byte[] context,
    byte[] encryptedKey
  );
}
