package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/** SLIP-0010 hardened Ed25519 derivation. Initialize LibHMACSha512 before use. */
public final class LibSLIP10Ed25519 {

  // @formatter:off
  public static final byte[] NAME = {'s','l','i','p','1','0'};
  public static final byte[] MASTER_KEY_LABEL = {'e','d','2','5','5','1','9',' ','s','e','e','d'};
  // @formatter:on

  public static final short EXTENDED_KEY_LENGTH = 64;
  private static final short KEY_LENGTH = 32;
  private static final short PATH_SEGMENT_LENGTH = 4;

  /**
   * Derives from a 64-byte master containing an Ed25519 seed and its chain code.
   * Writes the derived 32-byte Ed25519 seed followed by its 32-byte chain code.
   * Path components are big-endian hardened indices; an empty path selects the master.
   * Workspace size is independent of depth. Output may overlap master or path.
   */
  public static short derive(
    byte[] master,
    short masterOffset,
    short masterLength,
    byte[] path,
    short pathOffset,
    short pathLength,
    byte[] out,
    short outOffset
  ) {
    byte[] extendedKey = JCSystem.makeTransientByteArray(
      EXTENDED_KEY_LENGTH,
      JCSystem.CLEAR_ON_DESELECT
    );
    byte[] data = JCSystem.makeTransientByteArray(
      (short) (1 + KEY_LENGTH + PATH_SEGMENT_LENGTH),
      JCSystem.CLEAR_ON_DESELECT
    );
    byte[] block = JCSystem.makeTransientByteArray(
      LibHMACSha512.BLOCK_BYTES,
      JCSystem.CLEAR_ON_DESELECT
    );

    if (masterLength != EXTENDED_KEY_LENGTH || pathLength % PATH_SEGMENT_LENGTH != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    requireRange(master, masterOffset, masterLength);
    requireRange(path, pathOffset, pathLength);
    requireRange(out, outOffset, EXTENDED_KEY_LENGTH);

    for (short offset = 0; offset < pathLength; offset += PATH_SEGMENT_LENGTH) {
      if ((path[(short) (pathOffset + offset)] & (byte) 0x80) == 0) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    }

    Util.arrayCopyNonAtomic(master, masterOffset, extendedKey, (short) 0, EXTENDED_KEY_LENGTH);

    for (short offset = 0; offset < pathLength; offset += PATH_SEGMENT_LENGTH) {
      deriveChildKeyInPlace(extendedKey, path, (short) (pathOffset + offset), data, block);
    }

    Util.arrayCopyNonAtomic(extendedKey, (short) 0, out, outOffset, EXTENDED_KEY_LENGTH);

    return EXTENDED_KEY_LENGTH;
  }

  private static void deriveChildKeyInPlace(
    byte[] extendedKey,
    byte[] path,
    short pathSegmentOffset,
    byte[] data,
    byte[] block
  ) {
    data[0] = 0;
    Util.arrayCopyNonAtomic(extendedKey, (short) 0, data, (short) 1, KEY_LENGTH);
    Util.arrayCopyNonAtomic(
      path,
      pathSegmentOffset,
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
