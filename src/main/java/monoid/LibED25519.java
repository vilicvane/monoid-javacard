package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public final class LibED25519 {

  public static final byte SIGNATURE_LENGTH = 64;

  /**
   * Signs a complete message with pure Ed25519. Output may overlap the message.
   * Scratch secrets are erased on return; the caller owns and must clear the key.
   */
  public static short sign(
    CurveED25519 curve,
    ED25519Key privateKey,
    byte[] message,
    short messageOffset,
    short messageLength,
    byte[] out,
    short outOffset
  ) {
    byte[] publicNonce = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
    byte[] nonce = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
    byte[] response = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);

    try {
      curve.requirePrivateKey(privateKey);
      curve.hash.reset();
      curve.hash.update(privateKey.prefix, (short) 0, (short) 32);
      curve.hash.doFinal(message, messageOffset, messageLength, curve.work, (short) 0);
      Utils.reverse(curve.work, (short) 0, (short) 64);
      LibMath.mod(
        curve.work,
        (short) 0,
        (short) 64,
        CurveWEI25519.R,
        (short) 0,
        (short) 32,
        nonce,
        (short) 0
      );
      curve.multiplyBase(nonce, publicNonce, (short) 0);

      curve.hash.update(publicNonce, (short) 0, (short) 32);
      curve.hash.update(privateKey.publicKey, (short) 0, (short) 32);
      curve.hash.doFinal(message, messageOffset, messageLength, curve.work, (short) 0);
      Utils.reverse(curve.work, (short) 0, (short) 64);
      LibMath.mod(
        curve.work,
        (short) 0,
        (short) 64,
        CurveWEI25519.R,
        (short) 0,
        (short) 32,
        response,
        (short) 0
      );
      LibMath.modMult(
        response,
        (short) 0,
        privateKey.scalar,
        (short) 0,
        CurveWEI25519.R,
        (short) 0,
        response,
        (short) 0,
        (short) 32
      );
      LibMath.modAdd(
        response,
        (short) 0,
        nonce,
        (short) 0,
        CurveWEI25519.R,
        (short) 0,
        response,
        (short) 0,
        (short) 32
      );

      // Publish only after both hashes have consumed the complete message.
      Util.arrayCopyNonAtomic(response, (short) 0, out, (short) (outOffset + 32), (short) 32);
      Utils.reverse(out, (short) (outOffset + 32), (short) 32);
      Util.arrayCopyNonAtomic(publicNonce, (short) 0, out, outOffset, (short) 32);

      return SIGNATURE_LENGTH;
    } finally {
      Util.arrayFillNonAtomic(nonce, (short) 0, (short) nonce.length, (byte) 0);
      Util.arrayFillNonAtomic(response, (short) 0, (short) response.length, (byte) 0);
      Util.arrayFillNonAtomic(publicNonce, (short) 0, (short) publicNonce.length, (byte) 0);
      curve.clearScratch();
    }
  }
}
