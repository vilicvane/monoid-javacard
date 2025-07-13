package monoid;

import javacard.framework.*;
import javacard.security.*;
import monoidkeystore.*;

public final class KeystoreWrapper {
  private MonoidKeystore keystore;

  private static final byte[] lookupPublicKeyWBuffer = new byte[256];
  private static final byte[] publicKeyWBuffer = new byte[256];

  public KeystoreWrapper(MonoidKeystore keystore) {
    this.keystore = keystore;
  }

  public void verifyPIN(byte[] buffer, short offset, byte length) {
    keystore.verifyPIN(buffer, offset, length);
  }

  public KeyPair ensureOneECKeyPair(byte type) {
    byte[] keyPairTypes = keystore.getKeyPairTypes();

    KeyPair[] keyPairs;

    try {
      keyPairs = keystore.getKeyPairs();
    } catch (SecurityException e) {
      ISOException.throwIt(ISO7816.SW_NO_ERROR);
      return null;
    }

    short keyPairsLength = keystore.getKeyPairsLength();

    for (short index = 0; index < keyPairsLength; index++) {
      KeyPair keyPair = keyPairs[index];

      if (keyPairTypes[index] == type && keyPair.getPublic() instanceof ECPublicKey) {
        return keyPair;
      }
    }

    KeyPair pair;

    switch (type) {
      case Monoid.KEY_TYPE_ECDSA_SECP256K1:
        pair = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
        SECP256k1.setParameters((ECPrivateKey) pair.getPrivate());
        SECP256k1.setParameters((ECPublicKey) pair.getPublic());
        pair.genKeyPair();
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return null;
    }

    addECKeyPair(type, pair);

    return pair;
  }

  public void addECKeyPair(byte type, KeyPair pair) {
    short lookupPublicKeyWLength = ((ECPublicKey) pair.getPublic()).getW(lookupPublicKeyWBuffer, (short) 0);

    KeyPair existingKeyPair = getKeyPair(type, lookupPublicKeyWBuffer, (short) 0, lookupPublicKeyWLength);

    if (existingKeyPair != null) {
      return;
    }

    keystore.pushKeyPair(type, pair);
  }

  public KeyPair getKeyPair(byte type, byte[] publicKey, short publicKeyOffset, short publicKeyLength) {

    byte[] keyPairTypes = keystore.getKeyPairTypes();
    KeyPair[] keyPairs = keystore.getKeyPairs();
    short keyPairsLength = keystore.getKeyPairsLength();

    for (short index = 0; index < keyPairsLength; index++) {
      KeyPair keyPair = keyPairs[index];

      if (keyPairTypes[index] != type) {
        continue;
      }

      ECPublicKey keyPairPublicKey = (ECPublicKey) keyPair.getPublic();

      short comparingLength = keyPairPublicKey.getW(publicKeyWBuffer, (short) 0);

      if (comparingLength == publicKeyLength &&
          Util.arrayCompare(publicKey, publicKeyOffset,
              publicKeyWBuffer, (short) 0,
              publicKeyLength) == 0) {

        return keyPair;
      }
    }

    return null;
  }

  public void removeKeyPair(byte type, byte[] publicKey, short publicKeyOffset, short publicKeyLength) {

    KeyPair keyPair = getKeyPair(type, publicKey, publicKeyOffset, publicKeyLength);

    if (keyPair != null) {
      keystore.removeKeyPair(keyPair);
    }
  }

}
