package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.Signature;
import javacard.security.Signature.OneShot;

public class MonoidKeyPair {
  static final byte ALGORITHM_SECP256K1 = 1;
  static final byte ALGORITHM_ED25519 = 2;

  private byte algorithm;

  private KeyPair pair;

  MonoidKeyPair(byte algorithm, PublicKey publicKey, PrivateKey privateKey) {
    this.algorithm = algorithm;

    pair = new KeyPair(publicKey, privateKey);

    if (publicKey.isInitialized() != privateKey.isInitialized()) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    if (!publicKey.isInitialized()) {
      pair.genKeyPair();
    }
  }

  MonoidKeyPair(byte algorithm) {
    this.algorithm = algorithm;

    switch (algorithm) {
      case ALGORITHM_SECP256K1:
        pair = new KeyPair((ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) 256, false),
            (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 256, false));
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    pair.genKeyPair();
  }

  public short sign(Signature signature, byte[] inBuffer, short hashOffset, short hashLength, byte[] outBuffer,
      short outOffset) {
    signature.init(pair.getPrivate(), Signature.MODE_SIGN);
    return signature.signPreComputedHash(inBuffer, hashOffset, hashLength, outBuffer, outOffset);
  }
}
