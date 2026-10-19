package monoididentity;

import javacard.framework.Shareable;

/** Card-local identity and authenticated communication for Monoid. */
public interface IdentityShareable extends Shareable {
  /** The persistent four-byte random display ID generated at Identity installation. */
  public byte[] getId();

  /** The stable P-256 public key, encoded as an uncompressed 65-byte SEC 1 point. */
  public byte[] getPublicKey();

  /** SHA-256 of the installed Bundle key, or null when no Bundle is installed. */
  public byte[] getBundle();

  /** Replaces the Bundle after preparing packets in input member order, excluding this Identity. */
  public CommunicationDataShareable createBundle(byte[] publicKeys);

  /** Authenticates and installs a Bundle, returning the SHA-256 hash of its key. */
  public byte[] importBundle(byte[] senderPublicKey, byte[] data);

  /** Removes this Identity's Bundle without changing its identity key pair. */
  public void resetBundle();

  /** Encrypts an item using the Bundle when present, or the recipient Identity otherwise. */
  public CommunicationDataShareable encryptData(
    byte[] index,
    byte[] key,
    byte[] alias,
    short secret,
    byte[] recipientPublicKey,
    CommunicationDataShareable data
  );

  /** Returns secret (two bytes) || data only after authenticating the complete envelope. */
  public CommunicationDataShareable decryptData(
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] senderPublicKey,
    CommunicationDataShareable data
  );
}
