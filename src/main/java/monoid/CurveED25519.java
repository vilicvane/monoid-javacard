// Wei25519 conversion derived from JCEd25519 (MIT), Copyright (c) 2022 Antonin Dufka.
// See third-party/jced25519/PROVENANCE.md for source and licenses.
package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import monoidlib.Utils;

public class CurveED25519 extends EdwardsCurve {

  public static final byte KEY_LENGTH = 32;
  public static final byte PUBLIC_KEY_LENGTH = 32;

  private static final short KEY_BITS = 255;

  // @formatter:off
  private static final byte[] ONE = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
  };
  // @formatter:on

  final MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
  final byte[] work = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);

  private final ECPrivateKey sharedMultiplicationKey;
  private final KeyAgreement sharedECDH;
  private final byte[] transformX = JCSystem.makeTransientByteArray(
    KEY_LENGTH,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final byte[] transformY = JCSystem.makeTransientByteArray(
    KEY_LENGTH,
    JCSystem.CLEAR_ON_DESELECT
  );
  private ED25519Key sharedPrivateKey;

  public CurveED25519() {
    sharedMultiplicationKey = (ECPrivateKey) KeyBuilder.buildKey(
      KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
      JCSystem.MEMORY_TYPE_PERSISTENT,
      KEY_BITS,
      false
    );
    sharedECDH = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
  }

  @Override
  public short getKeyLength() {
    return KEY_LENGTH;
  }

  @Override
  public short getPublicKeyLength() {
    return PUBLIC_KEY_LENGTH;
  }

  @Override
  public ED25519Key getSharedPrivateKey(byte[] in, short keyOffset) {
    clear();
    ED25519Key privateKey = new ED25519Key();

    try {
      hash.doFinal(in, keyOffset, KEY_LENGTH, work, (short) 0);
      work[0] &= (byte) 0xF8;
      work[31] = (byte) ((work[31] & 0x3F) | 0x40);
      Util.arrayCopyNonAtomic(work, (short) 32, privateKey.prefix, (short) 0, (short) 32);
      Utils.reverse(work, (short) 0, KEY_LENGTH);
      LibMath.mod(
        work,
        (short) 0,
        KEY_LENGTH,
        CurveWEI25519.R,
        (short) 0,
        KEY_LENGTH,
        privateKey.scalar,
        (short) 0
      );
      multiplyBase(privateKey.scalar, privateKey.publicKey, (short) 0);
      privateKey.activate();
      sharedPrivateKey = privateKey;

      return privateKey;
    } finally {
      hash.reset();
    }
  }

  @Override
  public ED25519Key getSharedPrivateKey(DerivedKey key) {
    if (key.expandedKey == null) {
      ED25519Key privateKey = getSharedPrivateKey(key.key, (short) 0);
      byte[] expanded = new byte[KEY_LENGTH * 3];
      Util.arrayCopyNonAtomic(privateKey.scalar, (short) 0, expanded, (short) 0, KEY_LENGTH);
      Util.arrayCopyNonAtomic(privateKey.prefix, (short) 0, expanded, KEY_LENGTH, KEY_LENGTH);
      Util.arrayCopyNonAtomic(
        privateKey.publicKey,
        (short) 0,
        expanded,
        (short) (KEY_LENGTH * 2),
        PUBLIC_KEY_LENGTH
      );
      key.expandedKey = expanded;

      return privateKey;
    }

    clear();
    ED25519Key privateKey = new ED25519Key();
    Util.arrayCopyNonAtomic(key.expandedKey, (short) 0, privateKey.scalar, (short) 0, KEY_LENGTH);
    Util.arrayCopyNonAtomic(key.expandedKey, KEY_LENGTH, privateKey.prefix, (short) 0, KEY_LENGTH);
    Util.arrayCopyNonAtomic(
      key.expandedKey,
      (short) (KEY_LENGTH * 2),
      privateKey.publicKey,
      (short) 0,
      PUBLIC_KEY_LENGTH
    );
    privateKey.activate();
    sharedPrivateKey = privateKey;

    return privateKey;
  }

  @Override
  public short derivePublicKey(ED25519Key privateKey, byte[] out, short outOffset) {
    assertPrivateKey(privateKey);
    Util.arrayCopyNonAtomic(privateKey.publicKey, (short) 0, out, outOffset, PUBLIC_KEY_LENGTH);

    return PUBLIC_KEY_LENGTH;
  }

  void assertPrivateKey(ED25519Key privateKey) {
    if (privateKey == null || privateKey != sharedPrivateKey || !privateKey.isValid()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  public void clear() {
    if (sharedPrivateKey != null) {
      sharedPrivateKey.clear();
      sharedPrivateKey = null;
    }

    hash.reset();
  }

  void multiplyBase(byte[] scalar, byte[] out, short outOffset) {
    if (Utils.isZero(scalar)) {
      // Edwards identity, unavailable as a native affine point.
      Util.arrayFillNonAtomic(out, outOffset, PUBLIC_KEY_LENGTH, (byte) 0);
      out[outOffset] = 1;
      return;
    }

    if (!sharedMultiplicationKey.isInitialized()) {
      sharedMultiplicationKey.setFieldFP(CurveWEI25519.FP, (short) 0, KEY_LENGTH);
      sharedMultiplicationKey.setA(CurveWEI25519.A, (short) 0, KEY_LENGTH);
      sharedMultiplicationKey.setB(CurveWEI25519.B, (short) 0, KEY_LENGTH);
      sharedMultiplicationKey.setG(CurveWEI25519.G, (short) 0, (short) CurveWEI25519.G.length);
      sharedMultiplicationKey.setR(CurveWEI25519.R, (short) 0, KEY_LENGTH);
      // Plain ECDH uses the supplied prime-order base point without cofactor multiplication.
      sharedMultiplicationKey.setK((short) 1);
    }

    sharedMultiplicationKey.setS(scalar, (short) 0, KEY_LENGTH);
    sharedECDH.init(sharedMultiplicationKey);
    short length = sharedECDH.generateSecret(
      CurveWEI25519.G,
      (short) 0,
      (short) CurveWEI25519.G.length,
      work,
      (short) 0
    );

    if (length != work.length) {
      CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    }

    encodePoint(out, outOffset);
  }

  /** Birational Wei25519 -> compressed Edwards25519 mapping, from JCEd25519. */
  private void encodePoint(byte[] out, short outOffset) {
    LibMath.modSub(
      work,
      (short) 1,
      CurveWEI25519.TRANSFORM_A3,
      (short) 0,
      CurveWEI25519.FP,
      (short) 0,
      transformX,
      (short) 0,
      KEY_LENGTH
    );
    LibMath.modMult(
      transformX,
      (short) 0,
      CurveWEI25519.TRANSFORM_C,
      (short) 0,
      CurveWEI25519.FP,
      (short) 0,
      transformX,
      (short) 0,
      KEY_LENGTH
    );
    LibMath.modInv(
      work,
      (short) 33,
      CurveWEI25519.FP,
      (short) 0,
      transformY,
      (short) 0,
      KEY_LENGTH
    );
    LibMath.modMult(
      transformX,
      (short) 0,
      transformY,
      (short) 0,
      CurveWEI25519.FP,
      (short) 0,
      transformX,
      (short) 0,
      KEY_LENGTH
    );
    boolean negative = (transformX[(short) (KEY_LENGTH - 1)] & 1) != 0;

    LibMath.modSub(
      work,
      (short) 1,
      CurveWEI25519.TRANSFORM_A3,
      (short) 0,
      CurveWEI25519.FP,
      (short) 0,
      transformX,
      (short) 0,
      KEY_LENGTH
    );
    LibMath.modAdd(
      transformX,
      (short) 0,
      ONE,
      (short) 0,
      CurveWEI25519.FP,
      (short) 0,
      transformY,
      (short) 0,
      KEY_LENGTH
    );
    LibMath.modSub(
      transformX,
      (short) 0,
      ONE,
      (short) 0,
      CurveWEI25519.FP,
      (short) 0,
      transformX,
      (short) 0,
      KEY_LENGTH
    );
    LibMath.modInv(
      transformY,
      (short) 0,
      CurveWEI25519.FP,
      (short) 0,
      transformY,
      (short) 0,
      KEY_LENGTH
    );
    LibMath.modMult(
      transformX,
      (short) 0,
      transformY,
      (short) 0,
      CurveWEI25519.FP,
      (short) 0,
      out,
      outOffset,
      KEY_LENGTH
    );

    if (negative) {
      out[outOffset] |= (byte) 0x80;
    }

    Utils.reverse(out, outOffset, PUBLIC_KEY_LENGTH);
  }
}
