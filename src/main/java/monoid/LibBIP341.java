package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public final class LibBIP341 {

  private static final byte KEY_LENGTH = CurveSECP256k1.KEY_LENGTH;

  // @formatter:off
  private static final byte[] TWEAK_TAG = {'T','a','p','T','w','e','a','k'};

  // @formatter:on

  /**
   * Applies the BIP341 private-key tweak. A null Merkle root commits to no script
   * tree (BIP86); otherwise exactly 32 bytes are read. Output may overlap inputs.
   */
  public static short tweakPrivateKey(
    CurveSECP256k1 curve,
    byte[] key,
    short keyOffset,
    byte[] merkleRoot,
    short rootOffset,
    byte[] out,
    short outOffset
  ) {
    byte[] scalar = JCSystem.makeTransientByteArray(KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    byte[] publicKey = JCSystem.makeTransientByteArray((short) 33, JCSystem.CLEAR_ON_DESELECT);
    byte[] tweak = JCSystem.makeTransientByteArray(KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    byte[] tagHash = JCSystem.makeTransientByteArray(KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);

    try {
      Util.arrayCopyNonAtomic(key, keyOffset, scalar, (short) 0, KEY_LENGTH);
      LibBIP340.normalizePrivateKey(curve, scalar, publicKey);
      LibBIP340.beginTaggedHash(curve.hash, TWEAK_TAG, tagHash);
      curve.hash.update(publicKey, (short) 1, KEY_LENGTH);

      if (merkleRoot == null) {
        curve.hash.doFinal(publicKey, (short) 0, (short) 0, tweak, (short) 0);
      } else {
        curve.hash.doFinal(merkleRoot, rootOffset, KEY_LENGTH, tweak, (short) 0);
      }

      // BIP341 rejects an out-of-range tweak instead of reducing it modulo n.
      if (LibMath.compare(tweak, (short) 0, CurveSECP256k1.R, (short) 0, KEY_LENGTH) >= 0) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      }

      LibMath.modAdd(
        scalar,
        (short) 0,
        tweak,
        (short) 0,
        CurveSECP256k1.R,
        (short) 0,
        tweak,
        (short) 0,
        KEY_LENGTH
      );

      if (LibBIP340.isZero(tweak)) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      }

      Util.arrayCopyNonAtomic(tweak, (short) 0, out, outOffset, KEY_LENGTH);

      return KEY_LENGTH;
    } finally {
      curve.hash.reset();
    }
  }
}
