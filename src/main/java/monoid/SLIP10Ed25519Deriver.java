package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/** SLIP-0010 hardened Ed25519 derivation. Initialize LibHMACSha512 before use. */
public final class SLIP10Ed25519Deriver {

  public static final short EXTENDED_KEY_LENGTH = 64;
  private static final short KEY_LENGTH = 32;
  private static final short PATH_SEGMENT_LENGTH = 4;

  // @formatter:off
  private static final byte[] MASTER_KEY = {'e','d','2','5','5','1','9',' ','s','e','e','d'};
  // @formatter:on

  private final byte[] extendedKey = JCSystem.makeTransientByteArray(
    EXTENDED_KEY_LENGTH,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final byte[] data = JCSystem.makeTransientByteArray(
    (short) (1 + KEY_LENGTH + PATH_SEGMENT_LENGTH),
    JCSystem.CLEAR_ON_DESELECT
  );
  private final byte[] block = JCSystem.makeTransientByteArray(
    LibHMACSha512.BLOCK_BYTES,
    JCSystem.CLEAR_ON_DESELECT
  );

  /**
   * Writes a 32-byte Ed25519 seed followed by its 32-byte chain code.
   * Path components are big-endian hardened indices; an empty path selects the master.
   * Workspace size is independent of depth. Output may overlap seed or path.
   * Scratch secrets are erased on return; the caller owns and must erase the output.
   */
  public short derive(
    byte[] seed,
    short seedOffset,
    short seedLength,
    byte[] path,
    short pathOffset,
    short pathLength,
    byte[] out,
    short outOffset
  ) {
    try {
      if (seedLength < 16 || seedLength > 64 || pathLength % PATH_SEGMENT_LENGTH != 0) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }

      requireRange(seed, seedOffset, seedLength);
      requireRange(path, pathOffset, pathLength);
      requireRange(out, outOffset, EXTENDED_KEY_LENGTH);

      for (short offset = 0; offset < pathLength; offset += PATH_SEGMENT_LENGTH) {
        if ((path[(short) (pathOffset + offset)] & (byte) 0x80) == 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
      }

      LibHMACSha512.digest(
        MASTER_KEY,
        (short) 0,
        (short) MASTER_KEY.length,
        seed,
        seedOffset,
        seedLength,
        extendedKey,
        (short) 0,
        block
      );

      for (short offset = 0; offset < pathLength; offset += PATH_SEGMENT_LENGTH) {
        data[0] = 0;
        Util.arrayCopyNonAtomic(extendedKey, (short) 0, data, (short) 1, KEY_LENGTH);
        Util.arrayCopyNonAtomic(
          path,
          (short) (pathOffset + offset),
          data,
          (short) (1 + KEY_LENGTH),
          PATH_SEGMENT_LENGTH
        );
        LibHMACSha512.digest(
          extendedKey,
          KEY_LENGTH,
          KEY_LENGTH,
          data,
          (short) 0,
          (short) data.length,
          extendedKey,
          (short) 0,
          block
        );
      }

      Util.arrayCopyNonAtomic(extendedKey, (short) 0, out, outOffset, EXTENDED_KEY_LENGTH);

      return EXTENDED_KEY_LENGTH;
    } finally {
      clear();
    }
  }

  public void clear() {
    Util.arrayFillNonAtomic(extendedKey, (short) 0, EXTENDED_KEY_LENGTH, (byte) 0);
    Util.arrayFillNonAtomic(data, (short) 0, (short) data.length, (byte) 0);
    Util.arrayFillNonAtomic(block, (short) 0, (short) block.length, (byte) 0);
  }

  private static void requireRange(byte[] buffer, short offset, short length) {
    if (
      offset < 0 ||
      length < 0 ||
      length > buffer.length ||
      offset > (short) (buffer.length - length)
    ) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
  }
}
