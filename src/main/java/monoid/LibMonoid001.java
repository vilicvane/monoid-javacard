package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;

/** Monoid-001 HKDF-SHA512 derivation. Initialize LibHMACSha512 before use. */
public final class LibMonoid001 {

  // @formatter:off
  public static final byte[] NAME = {'m','o','n','o','i','d','-','0','0','1'};
  public static final byte[] MASTER_KEY_LABEL = {'M','o','n','o','i','d','-','0','0','1'};
  // @formatter:on

  public static final short MASTER_LENGTH = 64;
  private static final short KEY_LENGTH = CurveSECP256r1.KEY_LENGTH;

  /** Derives a P-256 scalar from a 64-byte HKDF PRK and opaque context. */
  public static byte[] derive(byte[] master, byte[] context) {
    short contextOffset = (short) (MASTER_KEY_LABEL.length + 1);
    short counterOffset = (short) (contextOffset + context.length);
    byte[] data = JCSystem.makeTransientByteArray(
      (short) (counterOffset + 2),
      JCSystem.CLEAR_ON_DESELECT
    );
    byte[] candidate = JCSystem.makeTransientByteArray(MASTER_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    byte[] block = JCSystem.makeTransientByteArray(
      LibHMACSha512.BLOCK_BYTES,
      JCSystem.CLEAR_ON_DESELECT
    );

    Util.arrayCopyNonAtomic(
      MASTER_KEY_LABEL,
      (short) 0,
      data,
      (short) 0,
      (short) MASTER_KEY_LABEL.length
    );
    Util.arrayCopyNonAtomic(context, (short) 0, data, contextOffset, (short) context.length);
    data[(short) (counterOffset + 1)] = 1;

    for (short counter = 0; counter < 256; counter++) {
      data[counterOffset] = (byte) counter;

      // HKDF-Expand's first block: HMAC(master, info || 0x01), truncated to 32 bytes.
      LibHMACSha512.digest(
        master,
        (short) 0,
        MASTER_LENGTH,
        data,
        (short) 0,
        (short) data.length,
        candidate,
        (short) 0,
        block
      );

      if (
        !Utils.isZero(candidate, (short) 0, KEY_LENGTH) &&
        LibMath.compare(candidate, (short) 0, CurveSECP256r1.R, (short) 0, KEY_LENGTH) < 0
      ) {
        return Utils.duplicateAsTransientDeselect(candidate, (short) 0, KEY_LENGTH);
      }
    }

    CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    return null;
  }
}
