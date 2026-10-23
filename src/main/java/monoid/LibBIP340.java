package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;

public final class LibBIP340 {

  public static final byte SIGNATURE_LENGTH = 64;

  private static final byte KEY_LENGTH = CurveSECP256k1.KEY_LENGTH;

  // @formatter:off
  private static final byte[] AUX_TAG = {'B','I','P','0','3','4','0','/','a','u','x'};
  private static final byte[] NONCE_TAG = {'B','I','P','0','3','4','0','/','n','o','n','c','e'};
  private static final byte[] CHALLENGE_TAG = {'B','I','P','0','3','4','0','/','c','h','a','l','l','e','n','g','e'};

  // @formatter:on

  /**
   * Signs a complete message using BIP340 and 32 bytes of auxiliary randomness.
   * Output may overlap the inputs; it is published after both message hashes.
   */
  public static short sign(
    CurveSECP256k1 curve,
    byte[] key,
    short keyOffset,
    byte[] message,
    short messageOffset,
    short messageLength,
    byte[] aux,
    short auxOffset,
    byte[] out,
    short outOffset
  ) {
    byte[] scalar = JCSystem.makeTransientByteArray(KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    byte[] publicKey = new byte[33];
    byte[] nonce = JCSystem.makeTransientByteArray(KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    byte[] publicNonce = new byte[33];
    byte[] response = JCSystem.makeTransientByteArray(KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    byte[] tagHash = new byte[KEY_LENGTH];

    try {
      Util.arrayCopyNonAtomic(key, keyOffset, scalar, (short) 0, KEY_LENGTH);
      normalizePrivateKey(curve, scalar, publicKey);

      beginTaggedHash(curve.hash, AUX_TAG, tagHash);
      curve.hash.doFinal(aux, auxOffset, KEY_LENGTH, response, (short) 0);

      for (short index = 0; index < KEY_LENGTH; index++) {
        response[index] ^= scalar[index];
      }

      beginTaggedHash(curve.hash, NONCE_TAG, tagHash);
      curve.hash.update(response, (short) 0, KEY_LENGTH);
      curve.hash.update(publicKey, (short) 1, KEY_LENGTH);
      curve.hash.doFinal(message, messageOffset, messageLength, nonce, (short) 0);
      reduceScalar(nonce);

      if (isZero(nonce)) {
        CryptoException.throwIt(CryptoException.ILLEGAL_USE);
      }

      normalizePrivateKey(curve, nonce, publicNonce);

      beginTaggedHash(curve.hash, CHALLENGE_TAG, tagHash);
      curve.hash.update(publicNonce, (short) 1, KEY_LENGTH);
      curve.hash.update(publicKey, (short) 1, KEY_LENGTH);
      curve.hash.doFinal(message, messageOffset, messageLength, response, (short) 0);
      reduceScalar(response);
      LibMath.modMult(
        response,
        (short) 0,
        scalar,
        (short) 0,
        CurveSECP256k1.R,
        (short) 0,
        response,
        (short) 0,
        KEY_LENGTH
      );
      LibMath.modAdd(
        response,
        (short) 0,
        nonce,
        (short) 0,
        CurveSECP256k1.R,
        (short) 0,
        response,
        (short) 0,
        KEY_LENGTH
      );

      Util.arrayCopyNonAtomic(publicNonce, (short) 1, out, outOffset, KEY_LENGTH);
      Util.arrayCopyNonAtomic(
        response,
        (short) 0,
        out,
        (short) (outOffset + KEY_LENGTH),
        KEY_LENGTH
      );

      return SIGNATURE_LENGTH;
    } finally {
      curve.hash.reset();
    }
  }

  static void beginTaggedHash(MessageDigest hash, byte[] tag, byte[] tagHash) {
    hash.reset();
    hash.doFinal(tag, (short) 0, (short) tag.length, tagHash, (short) 0);
    hash.update(tagHash, (short) 0, KEY_LENGTH);
    hash.update(tagHash, (short) 0, KEY_LENGTH);
  }

  /** Normalizes a private scalar to the even-Y representative used by BIP340. */
  static void normalizePrivateKey(CurveSECP256k1 curve, byte[] scalar, byte[] publicKey) {
    if (
      isZero(scalar) ||
      LibMath.compare(scalar, (short) 0, CurveSECP256k1.R, (short) 0, KEY_LENGTH) >= 0
    ) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    }

    curve.derivePublicKey(curve.getSharedPrivateKey(scalar, (short) 0), publicKey, (short) 0);

    if (publicKey[0] == (byte) 0x03) {
      LibMath.sub(CurveSECP256k1.R, (short) 0, scalar, (short) 0, scalar, (short) 0, KEY_LENGTH);
    }
  }

  static boolean isZero(byte[] scalar) {
    for (short index = 0; index < KEY_LENGTH; index++) {
      if (scalar[index] != 0) {
        return false;
      }
    }

    return true;
  }

  private static void reduceScalar(byte[] scalar) {
    // A 256-bit hash is below 2n, so at most one subtraction is needed.
    if (LibMath.compare(scalar, (short) 0, CurveSECP256k1.R, (short) 0, KEY_LENGTH) >= 0) {
      LibMath.sub(scalar, (short) 0, CurveSECP256k1.R, (short) 0, scalar, (short) 0, KEY_LENGTH);
    }
  }
}
