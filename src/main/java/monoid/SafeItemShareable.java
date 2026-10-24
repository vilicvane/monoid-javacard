package monoid;

import javacard.framework.Shareable;

/**
 * Restricted item handle. Every call checks the session and live Type grant; mutations require
 * writable permission. Array getters return global copies and array arguments must be global.
 */
public interface SafeItemShareable extends Shareable {
  byte[] getIndex();

  /** Returns null when no metadata is set. */
  byte[] getMetadata();

  /** Returns null when no alias is set. */
  byte[] getAlias();

  boolean isSecret();

  /** Rejects secret data. The returned reader also checks access on every call. */
  SafeDataShareable getData();

  /** A null alias removes the alias. */
  void setAlias(byte[] alias);

  /** Replaces data while preserving the secret flag. */
  void setData(SafeDataShareable data);

  /** Atomically replaces data and its secret flag. */
  void setData(SafeDataShareable data, boolean secret);

  /** May mark existing data secret; cannot make existing secret data public. */
  void setSecret(boolean secret);

  void remove();
}
