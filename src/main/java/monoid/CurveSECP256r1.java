package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

public class CurveSECP256r1 extends WeierstrassCurve {

  // SEC 2 v2, section 2.4.2.
  // @formatter:off
  public static final byte FP[] = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
  };

  public static final byte A[] = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
  };

  public static final byte B[] = {
      (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7,
      (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
      (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
      (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B
  };

  public static final byte G[] = {
      (byte) 0x04,
      (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47,
      (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2,
      (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0,
      (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96,
      (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B,
      (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16,
      (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE,
      (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5
  };

  public static final byte R[] = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
      (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51
  };
  // @formatter:on

  public static final byte K = (byte) 0x01;

  public static final short KEY_BITS = KeyBuilder.LENGTH_EC_FP_256;
  public static final byte KEY_LENGTH = KEY_BITS / 8;

  private ECPrivateKey sharedPrivateKey;

  private KeyAgreement sharedECDH;

  public CurveSECP256r1() {
    sharedPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(
      KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
      JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT,
      KeyBuilder.LENGTH_EC_FP_256,
      false
    );

    if (sharedPrivateKey == null) {
      // JCardSim fallback.
      KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP, KEY_BITS);
      sharedPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    }

    sharedECDH = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
  }

  @Override
  public short getKeyLength() {
    return KEY_LENGTH;
  }

  @Override
  public short getPublicKeyLength() {
    return 1 + KEY_LENGTH;
  }

  @Override
  public byte[] getR() {
    return R;
  }

  @Override
  public ECPrivateKey getSharedPrivateKey(byte[] in, short keyOffset) {
    if (!sharedPrivateKey.isInitialized()) {
      sharedPrivateKey.setFieldFP(FP, (short) 0x00, (short) FP.length);
      sharedPrivateKey.setA(A, (short) 0x00, (short) A.length);
      sharedPrivateKey.setB(B, (short) 0x00, (short) B.length);
      sharedPrivateKey.setG(G, (short) 0x00, (short) G.length);
      sharedPrivateKey.setR(R, (short) 0x00, (short) R.length);
      sharedPrivateKey.setK(K);
    }

    sharedPrivateKey.setS(in, keyOffset, KEY_LENGTH);

    return sharedPrivateKey;
  }

  /**
   * @return length of compressed public key
   */
  @Override
  public short derivePublicKey(ECPrivateKey privateKey, byte[] out, short outOffset) {
    sharedECDH.init(privateKey);

    byte[] publicKey = JCSystem.makeTransientByteArray(
      (short) (KEY_LENGTH * 2 + 1),
      JCSystem.CLEAR_ON_DESELECT
    );

    sharedECDH.generateSecret(G, (short) 0, (short) G.length, publicKey, (short) 0);

    return compressPublicKey(publicKey, (short) 0, out, outOffset);
  }

  /**
   * @return length of compressed public key
   */
  private short compressPublicKey(
    byte[] publicKey,
    short publicKeyOffset,
    byte[] out,
    short outOffset
  ) {
    out[outOffset] = (byte) ((publicKey[(short) (publicKeyOffset + KEY_LENGTH * 2)] & 1) != 0
        ? 0x03
        : 0x02);

    Util.arrayCopyNonAtomic(
      publicKey,
      (short) (publicKeyOffset + 1),
      out,
      (short) (outOffset + 1),
      KEY_LENGTH
    );

    return (short) (1 + KEY_LENGTH);
  }
}
