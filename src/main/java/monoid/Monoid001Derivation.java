package monoid;

import javacard.security.CryptoException;

/** Monoid-001 HKDF-SHA512 derivation. Initialize LibHMACSha512 before use. */
public final class Monoid001Derivation extends KeyDerivation {

  // @formatter:off
  public static final byte[] NAME = {'m','o','n','o','i','d','-','0','0','1'};
  public static final byte[] MASTER_KEY_LABEL = {'M','o','n','o','i','d','-','0','0','1'};
  // @formatter:on

  public static final short MASTER_LENGTH = 64;
  private static final short KEY_LENGTH = CurveSECP256r1.KEY_LENGTH;

  private byte[] workspace;

  @Override
  protected byte[] getMasterKeyLabel() {
    return MASTER_KEY_LABEL;
  }

  /** Derives a P-256 scalar from a 64-byte HKDF PRK and opaque context. */
  @Override
  protected byte[] deriveKey(byte[] master, byte[] context) {
    if (workspace == null) {
      workspace = new byte[MASTER_LENGTH];
    }

    for (short counter = 0; counter < 256; counter++) {
      // HKDF-Expand's first block: HMAC(master, info || 0x01), truncated to 32 bytes.
      LibHMACSha512.begin(master, (short) 0, MASTER_LENGTH);
      LibHMACSha512.update(MASTER_KEY_LABEL, (short) 0, (short) MASTER_KEY_LABEL.length);
      workspace[0] = 0;
      LibHMACSha512.update(workspace, (short) 0, (short) 1);
      LibHMACSha512.update(context, (short) 0, (short) context.length);
      workspace[0] = (byte) counter;
      workspace[1] = 1;
      LibHMACSha512.finish(workspace, (short) 0, (short) 2, workspace, (short) 0);

      if (
        !Utils.isZero(workspace, (short) 0, KEY_LENGTH) &&
        LibMath.compare(workspace, (short) 0, CurveSECP256r1.R, (short) 0, KEY_LENGTH) < 0
      ) {
        return Utils.duplicateAsPersistent(workspace, (short) 0, KEY_LENGTH);
      }
    }

    CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    return null;
  }
}
