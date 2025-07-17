package monoid;

import javacard.framework.*;
import javacard.security.*;

import monoidsafe.MonoidSafe;

public final class Keystore {
  public static final byte TYPE_SECP256K1 = 0x01;

  public static final byte SAFE_INDEX_DIGEST_LENGTH = 8;
  public static final byte SAFE_INDEX_LENGTH = 1 + SAFE_INDEX_DIGEST_LENGTH;

  private MonoidSafe safe;

  private KeyPair keyPair;

  public Keystore(MonoidSafe safe) {
    this.safe = safe;
    this.keyPair = new KeyPair(KeyPair.ALG_EC_FP, LibSECP256k1.KEY_BITS);
  }

  public short genKey(byte type, byte[] output, short outputOffset) {
    switch (type) {
      case TYPE_SECP256K1:
        return genSECP256K1Key(output, outputOffset);
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return 0;
    }
  }

  private short genSECP256K1Key(byte[] output, short outputOffset) {
    ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

    LibSECP256k1.setDomainParameters(privateKey);
    LibSECP256k1.setDomainParameters(publicKey);

    keyPair.genKeyPair();

    byte[] buffer = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);

    publicKey.getW(buffer, (short) 0);

    short publicKeyLength = LibSECP256k1.compressPublicKey(buffer, (short) 0, output, outputOffset);

    OneShot.digest(MessageDigest.ALG_SHA_256, output, outputOffset, publicKeyLength, buffer, (short) 0);

    byte[] privateKeyBuffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE,
        (short) (SAFE_INDEX_LENGTH + LibSECP256k1.KEY_BYTES));

    privateKeyBuffer[0] = TYPE_SECP256K1;

    // Copy the first SAFE_INDEX_DIGEST_LENGTH bytes of the digest to the private
    // key buffer (as part of the index).
    Util.arrayCopyNonAtomic(buffer, (short) 0, privateKeyBuffer, (short) 1, SAFE_INDEX_DIGEST_LENGTH);

    privateKey.getS(privateKeyBuffer, SAFE_INDEX_LENGTH);

    safe.set(privateKeyBuffer, (short) 0, SAFE_INDEX_LENGTH, (short) privateKeyBuffer.length);

    return publicKeyLength;
  }

  public short sign(
      byte[] in,
      short indexOffset,
      short digestOffset, byte digestLength,
      byte[] out, short outOffset) {

    short privateKeyBufferLength = (short) (SAFE_INDEX_LENGTH + LibSECP256k1.KEY_BYTES);

    byte[] privateKeyBuffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, privateKeyBufferLength);

    Util.arrayCopyNonAtomic(in, indexOffset, privateKeyBuffer, (short) 0, SAFE_INDEX_LENGTH);

    if (safe.get(privateKeyBuffer, (short) 0, SAFE_INDEX_LENGTH) != privateKeyBufferLength) {
      ISOException.throwIt(ISO7816.SW_FILE_INVALID);
    }

    Key privateKey;

    switch (privateKeyBuffer[0]) {
      case TYPE_SECP256K1:
        privateKey = LibSECP256k1.getSharedPrivateKey(privateKeyBuffer, SAFE_INDEX_LENGTH);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return 0;
    }

    short length = OneShot.sign(
        Signature.SIG_CIPHER_ECDSA_PLAIN,
        privateKey,
        in, digestOffset, digestLength,
        out, outOffset);

    LibECDSA.ensureLowS(out, outOffset);

    return length;
  }
}
