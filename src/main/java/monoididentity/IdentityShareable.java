package monoididentity;

import javacard.framework.Shareable;

/** Card-local identity and authenticated communication isolated by caller AID. */
public interface IdentityShareable extends Shareable {
  /** A stable private 32-byte token derived for the runtime caller's complete AID. */
  public byte[] getToken();

  /** The persistent four-byte display ID selected at installation and retained by reset. */
  public byte[] getId();

  /** The stable P-256 public key, encoded as an uncompressed 65-byte SEC 1 point. */
  public byte[] getPublicKey();

  /** SHA-256 of the installed Bundle key, or null when no Bundle is installed. */
  public byte[] getBundle();

  /** The installed Authority service URL as global UTF-8 bytes, or null when not configured. */
  public byte[] getAuthority();

  /**
   * Verifies version 1 time data against the installed Authority and caller-owned challenge.
   * All inputs must be global arrays: data is 41 bytes, raw r || s is 64 bytes, and challenge is 32
   * bytes. The caller owns challenge generation, freshness and one-use consumption.
   */
  public void verifyAuthorityTime(byte[] data, byte[] signature, byte[] challenge);

  /** Whether the persistent Secret PIN has been initialized. */
  public boolean isSecretPINSet();

  public short getSecretPINTriesRemaining();

  /** Verifies a global PIN buffer and authorizes only the current caller. */
  public boolean checkSecretPIN(byte[] pin);

  /** Monoid only: initializes the PIN, or changes it after Secret authentication. */
  public void updateSecretPIN(byte[] pin);

  /** A multi-bit authorization result for the current caller. */
  public short getSecretPINValidationResult();

  public void clearSecretAuth();

  /** Monoid only: creates for self and these other recipients; requires no local Bundle. */
  public CommunicationDataShareable createBundle(byte[] publicKeys);

  /** Monoid only: joins from a member or installed Authority; the same key and policy are idempotent. */
  public byte[] joinBundle(byte[] senderPublicKey, byte[] data);

  /** Monoid only: requests this recipient's admission using Bundle possession and this Identity. */
  public CommunicationDataShareable extendBundle(byte[] publicKey);

  /** Monoid only: approves another member's request and encrypts enrollment for its recipient. */
  public CommunicationDataShareable approveBundleExtension(byte[] request);

  /** Monoid only: prepares a new identity outside a transaction and returns its caller token. */
  public byte[] prepareReset();

  /** Publishes the prepared identity within Monoid's transaction that also clears its state. */
  public void reset();

  /** Encrypts for the same caller AID, using the Bundle when present or the recipient otherwise. */
  public CommunicationDataShareable encryptData(
    byte[] index,
    byte[] metadata,
    byte[] alias,
    short secret,
    byte[] recipientPublicKey,
    CommunicationDataShareable data
  );

  /** Returns secret (two bytes) || data after authenticating the envelope for this caller AID. */
  public CommunicationDataShareable decryptData(
    byte[] index,
    byte[] metadata,
    byte[] alias,
    byte[] senderPublicKey,
    CommunicationDataShareable data
  );
}
