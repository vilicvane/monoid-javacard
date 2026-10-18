package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/** SLIP-0010 hardened Ed25519 derivation. Initialize LibHMACSha512 before use. */
public final class SLIP10Ed25519Derivation extends KeyDerivation {

  // @formatter:off
  public static final byte[] NAME = {'s','l','i','p','1','0'};
  public static final byte[] MASTER_KEY_LABEL = {'e','d','2','5','5','1','9',' ','s','e','e','d'};
  // @formatter:on

  public static final short EXTENDED_KEY_LENGTH = 64;
  private static final short KEY_LENGTH = 32;
  private static final short PATH_SEGMENT_LENGTH = 4;

  @Override
  protected byte[] getMasterKeyLabel() {
    return MASTER_KEY_LABEL;
  }

  /**
   * Derives from a 64-byte master containing an Ed25519 seed and its chain code.
   * Returns the derived 32-byte Ed25519 seed followed by its 32-byte chain code.
   * Path components are big-endian hardened indices; an empty path selects the master.
   * Workspace size is independent of depth. Inputs remain unchanged.
   */
  @Override
  protected byte[] deriveKey(byte[] master, byte[] path) {
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

    if (master.length != EXTENDED_KEY_LENGTH || path.length % PATH_SEGMENT_LENGTH != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    for (short offset = 0; offset < path.length; offset += PATH_SEGMENT_LENGTH) {
      if ((path[offset] & (byte) 0x80) == 0) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    }

    Util.arrayCopyNonAtomic(master, (short) 0, extendedKey, (short) 0, EXTENDED_KEY_LENGTH);

    for (short offset = 0; offset < path.length; offset += PATH_SEGMENT_LENGTH) {
      deriveChildKeyInPlace(extendedKey, path, offset, data, block);
    }

    return extendedKey;
  }

  private void deriveChildKeyInPlace(
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
}
