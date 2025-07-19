package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

public class CurveSECP256k1 extends Curve {
  public static final byte FP[] = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC, (byte) 0x2F
  };

  public static final byte A[] = {
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
  };

  public static final byte B[] = {
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x07
  };

  public static final byte G[] = {
      (byte) 0x04,
      (byte) 0x79, (byte) 0xBE, (byte) 0x66, (byte) 0x7E, (byte) 0xF9, (byte) 0xDC, (byte) 0xBB, (byte) 0xAC,
      (byte) 0x55, (byte) 0xA0, (byte) 0x62, (byte) 0x95, (byte) 0xCE, (byte) 0x87, (byte) 0x0B, (byte) 0x07,
      (byte) 0x02, (byte) 0x9B, (byte) 0xFC, (byte) 0xDB, (byte) 0x2D, (byte) 0xCE, (byte) 0x28, (byte) 0xD9,
      (byte) 0x59, (byte) 0xF2, (byte) 0x81, (byte) 0x5B, (byte) 0x16, (byte) 0xF8, (byte) 0x17, (byte) 0x98,
      (byte) 0x48, (byte) 0x3A, (byte) 0xDA, (byte) 0x77, (byte) 0x26, (byte) 0xA3, (byte) 0xC4, (byte) 0x65,
      (byte) 0x5D, (byte) 0xA4, (byte) 0xFB, (byte) 0xFC, (byte) 0x0E, (byte) 0x11, (byte) 0x08, (byte) 0xA8,
      (byte) 0xFD, (byte) 0x17, (byte) 0xB4, (byte) 0x48, (byte) 0xA6, (byte) 0x85, (byte) 0x54, (byte) 0x19,
      (byte) 0x9C, (byte) 0x47, (byte) 0xD0, (byte) 0x8F, (byte) 0xFB, (byte) 0x10, (byte) 0xD4, (byte) 0xB8
  };

  public static final byte R[] = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE,
      (byte) 0xBA, (byte) 0xAE, (byte) 0xDC, (byte) 0xE6, (byte) 0xAF, (byte) 0x48, (byte) 0xA0, (byte) 0x3B,
      (byte) 0xBF, (byte) 0xD2, (byte) 0x5E, (byte) 0x8C, (byte) 0xD0, (byte) 0x36, (byte) 0x41, (byte) 0x41
  };

  public static final byte K = (byte) 0x01;

  public static final short KEY_BITS = KeyBuilder.LENGTH_EC_FP_256;
  public static final byte KEY_LENGTH = KEY_BITS / 8;

  private ECPrivateKey sharedPrivateKey;

  private KeyAgreement sharedECDH;

  public CurveSECP256k1() {
    sharedPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
        JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false);

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

    byte[] publicKey = JCSystem.makeTransientByteArray((short) (KEY_LENGTH * 2 + 1),
        JCSystem.CLEAR_ON_DESELECT);

    sharedECDH.generateSecret(G, (short) 0, (short) G.length, publicKey, (short) 0);

    return compressPublicKey(publicKey, (short) 0, out, outOffset);
  }

  /**
   * @return length of compressed public key
   */
  private short compressPublicKey(byte[] publicKey, short publicKeyOffset, byte[] out, short outOffset) {
    out[outOffset] = (byte) ((publicKey[(short) (publicKeyOffset + KEY_LENGTH * 2)] & 1) != 0 ? 0x03 : 0x02);

    Util.arrayCopyNonAtomic(
        publicKey, (short) (publicKeyOffset + 1),
        out, (short) (outOffset + 1),
        KEY_LENGTH);

    return (short) (1 + KEY_LENGTH);
  }
}
