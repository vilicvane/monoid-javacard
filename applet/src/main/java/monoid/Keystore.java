package monoid;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;
import monoidstore.*;

public final class Keystore {
  public static final byte STORE_INDEX_DIGEST_LENGTH = 8;
  public static final byte STORE_INDEX_LENGTH = 1 + STORE_INDEX_DIGEST_LENGTH;

  private MonoidStore store;

  private ECPrivateKey ecPrivateKey;

  public Keystore(MonoidStore store) {
    this.store = store;

    ecPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
        JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, (short) 256, false);
  }

  public short genKey(byte type, byte[] output, short outputOffset) {
    switch (type) {
      case Constants.STORE_ITEM_TYPE_SECP256K1:
        return genSECP256K1Key(output, outputOffset);
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return 0;
    }
  }

  private short genSECP256K1Key(byte[] output, short outputOffset) {
    KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP, SECP256k1.KEY_BITS);

    ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

    SECP256k1.setParameters(privateKey);
    SECP256k1.setParameters(publicKey);

    keyPair.genKeyPair();

    byte[] buffer = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);

    short wLength = publicKey.getW(buffer, (short) 0);

    short publicKeyLength = (short) (wLength - 1); // First byte is 0x04 (uncompressed).

    Util.arrayCopyNonAtomic(buffer, (short) 1, output, outputOffset, publicKeyLength);

    MessageDigest.OneShot digest = MessageDigest.OneShot.open(MessageDigest.ALG_SHA_256);

    digest.doFinal(
        buffer, (short) 1, (short) (wLength - 1),
        buffer, (short) 0);

    digest.close();

    byte[] privateKeyBuffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE,
        (short) (STORE_INDEX_LENGTH + SECP256k1.KEY_BYTES));

    privateKeyBuffer[0] = Constants.STORE_ITEM_TYPE_SECP256K1;

    // Copy the first STORE_INDEX_DIGEST_LENGTH bytes of the digest to the private
    // key buffer (as part of the index).
    Util.arrayCopyNonAtomic(buffer, (short) 0, privateKeyBuffer, (short) 1, STORE_INDEX_DIGEST_LENGTH);

    privateKey.getS(privateKeyBuffer, STORE_INDEX_LENGTH);

    store.set(privateKeyBuffer, (short) 0, STORE_INDEX_LENGTH, (short) privateKeyBuffer.length);

    return publicKeyLength;
  }

  public short sign(byte[] input, short indexOffset, short hashOffset, byte hashLength, byte[] output,
      short outputOffset) {

    short privateKeyBufferLength = (short) (STORE_INDEX_LENGTH + SECP256k1.KEY_BYTES);

    byte[] privateKeyBuffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, privateKeyBufferLength);

    Util.arrayCopyNonAtomic(input, indexOffset, privateKeyBuffer, (short) 0, STORE_INDEX_LENGTH);

    if (store.get(privateKeyBuffer, (short) 0, (byte) STORE_INDEX_LENGTH) != privateKeyBufferLength) {
      ISOException.throwIt(ISO7816.SW_FILE_INVALID);
    }

    Key privateKey;

    switch (privateKeyBuffer[0]) {
      case Constants.STORE_ITEM_TYPE_SECP256K1:
        SECP256k1.setParameters(ecPrivateKey);
        ecPrivateKey.setS(privateKeyBuffer, STORE_INDEX_LENGTH, SECP256k1.KEY_BYTES);
        privateKey = ecPrivateKey;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return 0;
    }

    Signature.OneShot signature = Signature.OneShot.open(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_ECDSA_PLAIN,
        Cipher.PAD_NULL);

    signature.init(privateKey, Signature.MODE_SIGN);

    // Note that this doesn't guarantee low-S signatures, fix it on the client side.
    short length = signature.signPreComputedHash(input, hashOffset, hashLength, output, outputOffset);

    signature.close();

    return length;
  }
}
