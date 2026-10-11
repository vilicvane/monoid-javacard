// Wei25519 conversion derived from JCEd25519 (MIT), Copyright (c) 2022 Antonin Dufka.
// See third-party/jced25519/PROVENANCE.md for source and licenses.
package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * Experimental pure Ed25519, using JCEd25519's Wei25519 hardware acceleration.
 * This math backend is NOT constant time. Do not treat correctness tests as a security audit.
 * One owner per applet; operations are serialized and no point arithmetic is offloaded.
 */
public final class ED25519Signer {

  final MathResources resources;
  final ECCurve curve;
  final MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
  final MessageDigest commitmentHash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
  final byte[] work = transientBytes((short) 65);
  private final ECPoint point;
  private final BigNat transformC;
  private final BigNat transformA3;
  private final BigNat transformX;
  private final BigNat transformY;
  private ED25519Key key;
  private ED25519SigningSession active;

  public ED25519Signer() {
    // The existing Monoid card already supports full XY ECDH. No vendor applet API is used.
    MathSupport.getInstance().setCard(MathSupport.JCOP4_P71);
    resources = new MathResources((short) 256);
    curve = new ECCurve(
      CurveWEI25519.FP,
      CurveWEI25519.A,
      CurveWEI25519.B,
      CurveWEI25519.G,
      CurveWEI25519.R,
      CurveWEI25519.K,
      resources
    );
    point = new ECPoint(curve);
    transformC = constant(CurveWEI25519.TRANSFORM_C);
    transformA3 = constant(CurveWEI25519.TRANSFORM_A3);
    transformX = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, resources);
    transformY = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, resources);
  }

  private BigNat constant(byte[] bytes) {
    BigNat value = new BigNat((short) bytes.length, JCSystem.MEMORY_TYPE_PERSISTENT, resources);

    value.fromByteArray(bytes, (short) 0, (short) bytes.length);

    return value;
  }

  /** Import exactly 32 bytes of seed, invalidating all earlier keys and sessions. */
  public void importSeed(byte[] seed, short offset) {
    clear();
    curve.updateAfterReset();
    ED25519Key imported = new ED25519Key(resources);

    try {
      hash.doFinal(seed, offset, (short) 32, work, (short) 0);
      work[0] &= (byte) 0xF8;
      work[31] = (byte) ((work[31] & 0x3F) | 0x40);
      Util.arrayCopyNonAtomic(work, (short) 32, imported.prefix, (short) 0, (short) 32);
      reverse(work, (short) 0, (short) 32);
      imported.scalar.fromByteArray(work, (short) 0, (short) 32);
      imported.scalar.mod(curve.rValue);
      imported.scalar.resize((short) 32);
      multiplyBase(imported.scalar, imported.publicKey, (short) 0);
      imported.activate();
      key = imported;
    } finally {
      if (key != imported) {
        imported.clear();
      }

      clearScratch();
    }
  }

  public short getPublicKey(byte[] output, short offset) {
    requireKey();
    Util.arrayCopyNonAtomic(key.publicKey, (short) 0, output, offset, (short) 32);

    return 32;
  }

  public ED25519SigningSession begin() {
    abort();
    requireKey();
    active = new ED25519SigningSession(this, key);

    return active;
  }

  private void requireKey() {
    if (key == null || !key.isValid()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  void requireActive(ED25519SigningSession session) {
    requireKey();

    if (active != session) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  void release(ED25519SigningSession session) {
    if (active == session) {
      active = null;
      hash.reset();
      commitmentHash.reset();
      clearScratch();
    }
  }

  public void abort() {
    if (active != null) {
      active.clear();
    }

    hash.reset();
    commitmentHash.reset();
    clearScratch();
  }

  public void clear() {
    abort();

    if (key != null) {
      key.clear();
    }

    key = null;
  }

  void clearScratch() {
    resources.erase();
    transformX.erase();
    transformY.erase();
    curve.sharedPrivateKey.clearKey();
    erase(work);
  }

  void multiplyBase(BigNat scalar, byte[] output, short offset) {
    if (scalar.equals((byte) 0)) {
      Util.arrayFillNonAtomic(output, offset, (short) 32, (byte) 0);
      output[offset] = 1;
      // Edwards identity, unavailable as a native affine point.
      return;
    }

    curve.updateAfterReset();
    point.setW(CurveWEI25519.G, (short) 0, (short) CurveWEI25519.G.length);
    point.multiplication(scalar);
    encodePoint(output, offset);
  }

  /** Birational Wei25519 -> compressed Edwards25519 mapping, from JCEd25519. */
  private void encodePoint(byte[] output, short offset) {
    point.getW(work, (short) 0);
    transformX.fromByteArray(work, (short) 1, (short) 32);
    transformY.fromByteArray(work, (short) 33, (short) 32);
    transformX.modSub(transformA3, curve.pValue);
    transformX.modMult(transformC, curve.pValue);
    transformY.modInv(curve.pValue);
    transformX.modMult(transformY, curve.pValue);
    boolean negative = transformX.isOdd();

    transformX.fromByteArray(work, (short) 1, (short) 32);
    transformX.modSub(transformA3, curve.pValue);
    transformY.clone(transformX);
    transformX.decrement();
    transformY.increment();
    transformY.mod(curve.pValue);
    transformY.modInv(curve.pValue);
    transformX.modMult(transformY, curve.pValue);
    transformX.prependZeros((short) 32, output, offset);

    if (negative) {
      output[offset] |= (byte) 0x80;
    }

    reverse(output, offset, (short) 32);
  }

  static byte[] transientBytes(short length) {
    return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);
  }

  static void erase(byte[] bytes) {
    Util.arrayFillNonAtomic(bytes, (short) 0, (short) bytes.length, (byte) 0);
  }

  static void reverse(byte[] bytes, short offset, short length) {
    for (short i = 0; i < (short) (length / 2); i++) {
      short left = (short) (offset + i);
      short right = (short) (offset + length - i - 1);
      byte value = bytes[left];

      bytes[left] = bytes[right];
      bytes[right] = value;
    }
  }
}
