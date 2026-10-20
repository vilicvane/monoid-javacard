package monoididentity;

import javacard.framework.Shareable;

/** Card-local identity and authenticated communication isolated by caller AID. */
public interface IdentityShareable extends Shareable {
  /** A stable private 32-byte token derived for the runtime caller's complete AID. */
  public byte[] getToken();

  /** The persistent four-byte random display ID generated at Identity installation. */
  public byte[] getId();

  /** The stable P-256 public key, encoded as an uncompressed 65-byte SEC 1 point. */
  public byte[] getPublicKey();

  /** SHA-256 of the installed Bundle key, or null when no Bundle is installed. */
  public byte[] getBundle();

  /** Monoid only: replaces the Bundle and prepares member packets, excluding this Identity. */
  public CommunicationDataShareable createBundle(byte[] publicKeys);

  /** Monoid only: authenticates and installs a Bundle, returning the SHA-256 hash of its key. */
  public byte[] importBundle(byte[] senderPublicKey, byte[] data);

  /** Monoid only: removes this Identity's Bundle without changing its identity key pair. */
  public void resetBundle();

  /** Encrypts for the same caller AID, using the Bundle when present or the recipient otherwise. */
  public CommunicationDataShareable encryptData(
    byte[] index,
    byte[] key,
    byte[] alias,
    short secret,
    byte[] recipientPublicKey,
    CommunicationDataShareable data
  );

  /** Returns secret (two bytes) || data after authenticating the envelope for this caller AID. */
  public CommunicationDataShareable decryptData(
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] senderPublicKey,
    CommunicationDataShareable data
  );
}
