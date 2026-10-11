package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Two-pass deterministic signing without buffering the message. The second pass MUST
 * match the first: releasing two challenges with one nonce would disclose the private key.
 * A SHA-256 commitment and exact length bind the passes. Any failed operation consumes
 * the session. State and secrets clear on deselect; callers may then release the object to GC.
 */
public final class ED25519SigningSession {

  private static final byte NONCE = 1;
  private static final byte CHALLENGE = 2;
  private final ED25519Signer owner;
  private final ED25519Key key;
  private final byte[] state = ED25519Signer.transientBytes((short) 1);
  private final short[] lengths = JCSystem.makeTransientShortArray(
    (short) 2,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final byte[] commitment = ED25519Signer.transientBytes((short) 32);
  private final byte[] publicNonce = ED25519Signer.transientBytes((short) 32);
  private final BigNat nonce;
  private final BigNat response;

  ED25519SigningSession(ED25519Signer owner, ED25519Key key) {
    this.owner = owner;
    this.key = key;
    nonce = new BigNat((short) 64, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, owner.resources);
    response = new BigNat((short) 64, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, owner.resources);
    owner.hash.reset();
    owner.commitmentHash.reset();
    owner.hash.update(key.prefix, (short) 0, (short) 32);
    state[0] = NONCE;
  }

  /** Append to the current pass. Messages up to 32767 bytes; chunks can differ between passes. */
  public void update(byte[] message, short offset, short length) {
    boolean success = false;

    try {
      requirePhase(state[0]);
      short index = (short) (state[0] - 1);

      if (length < 0 || lengths[index] > (short) (32767 - length)) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }

      owner.hash.update(message, offset, length);
      owner.commitmentHash.update(message, offset, length);
      lengths[index] += length;
      success = true;
    } finally {
      if (!success) {
        clear();
      }
    }
  }

  /** End the nonce pass and begin replaying the same message for the challenge. */
  public void finishFirstPass() {
    boolean success = false;

    try {
      requirePhase(NONCE);
      owner.hash.doFinal(owner.work, (short) 0, (short) 0, owner.work, (short) 0);
      ED25519Signer.reverse(owner.work, (short) 0, (short) 64);
      nonce.fromByteArray(owner.work, (short) 0, (short) 64);
      nonce.mod(owner.curve.rValue);
      nonce.resize((short) 32);
      owner.commitmentHash.doFinal(owner.work, (short) 0, (short) 0, commitment, (short) 0);
      owner.multiplyBase(nonce, publicNonce, (short) 0);
      owner.hash.update(publicNonce, (short) 0, (short) 32);
      owner.hash.update(key.publicKey, (short) 0, (short) 32);
      state[0] = CHALLENGE;
      success = true;
    } finally {
      owner.clearScratch();

      if (!success) {
        clear();
      }
    }
  }

  /** Returns the standard 64-byte R || S signature, consuming this session. */
  public short finish(byte[] output, short offset) {
    try {
      requirePhase(CHALLENGE);
      owner.commitmentHash.doFinal(owner.work, (short) 0, (short) 0, owner.work, (short) 0);

      if (
        lengths[0] != lengths[1] ||
        Util.arrayCompare(commitment, (short) 0, owner.work, (short) 0, (short) 32) != 0
      ) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }

      owner.hash.doFinal(owner.work, (short) 0, (short) 0, owner.work, (short) 0);
      ED25519Signer.reverse(owner.work, (short) 0, (short) 64);
      response.fromByteArray(owner.work, (short) 0, (short) 64);
      response.mod(owner.curve.rValue);
      response.resize((short) 32);
      response.modMult(key.scalar, owner.curve.rValue);
      response.modAdd(nonce, owner.curve.rValue);
      response.prependZeros((short) 32, output, (short) (offset + 32));
      ED25519Signer.reverse(output, (short) (offset + 32), (short) 32);
      Util.arrayCopyNonAtomic(publicNonce, (short) 0, output, offset, (short) 32);

      return 64;
    } finally {
      clear();
    }
  }

  private void requirePhase(byte phase) {
    owner.requireActive(this);

    if ((phase != NONCE && phase != CHALLENGE) || state[0] != phase) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  public void clear() {
    state[0] = 0;
    lengths[0] = 0;
    lengths[1] = 0;
    nonce.erase();
    response.erase();
    ED25519Signer.erase(commitment);
    ED25519Signer.erase(publicNonce);
    owner.release(this);
  }
}
