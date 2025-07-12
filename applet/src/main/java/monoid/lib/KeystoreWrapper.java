package monoid.lib;

import javacard.framework.*;
import javacard.security.*;
import monoid.Monoid;
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
    MonoidKeystoreItem[] items = keystore.getItems();
    short itemsLength = keystore.getItemsLength();

    for (short index = 0; index < itemsLength; index++) {
      MonoidKeystoreItem item = items[index];

      if (item.type == type && item.pair.getPublic() instanceof ECPublicKey) {
        return item.pair;
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
    MonoidKeystoreItem[] items = keystore.getItems();
    short itemsLength = keystore.getItemsLength();

    short lookupPublicKeyWLength = ((ECPublicKey) pair.getPublic()).getW(lookupPublicKeyWBuffer, (short) 0);

    short index = findECKeyPairItemIndex(type, items, itemsLength, lookupPublicKeyWBuffer, (short) 0,
        lookupPublicKeyWLength);

    if (index >= 0) {
      return;
    }

    JCSystem.beginTransaction();

    if (itemsLength == items.length) {
      keystore.extendItems();

      items = keystore.getItems();
      itemsLength = keystore.getItemsLength();
    }

    items[itemsLength] = new MonoidKeystoreItem(type, pair);

    itemsLength++;

    keystore.setItemsLength(itemsLength);

    JCSystem.commitTransaction();
  }

  public KeyPair getKeyPair(byte type, byte[] publicKey, short publicKeyOffset, short publicKeyLength) {
    MonoidKeystoreItem[] items = keystore.getItems();
    short itemsLength = keystore.getItemsLength();

    short index = findECKeyPairItemIndex(type, items, itemsLength, publicKey, publicKeyOffset, publicKeyLength);

    return index >= 0 ? items[index].pair : null;
  }

  public void removeKeyPair(byte type, byte[] publicKey, short publicKeyOffset, short publicKeyLength) {
    MonoidKeystoreItem[] items = keystore.getItems();
    short itemsLength = keystore.getItemsLength();

    short indexToRemove = findECKeyPairItemIndex(type, items, itemsLength, publicKey, publicKeyOffset, publicKeyLength);

    if (indexToRemove < 0) {
      return;
    }

    JCSystem.beginTransaction();

    for (short index = indexToRemove; index < itemsLength - 1; index++) {
      items[index] = items[index + 1];
    }

    items[itemsLength] = null;

    itemsLength--;

    keystore.setItemsLength(itemsLength);

    JCSystem.commitTransaction();
  }

  private short findECKeyPairItemIndex(byte type, MonoidKeystoreItem[] items, short itemsLength, byte[] publicKey,
      short publicKeyOffset, short publicKeyLength) {
    for (short index = 0; index < itemsLength; index++) {
      MonoidKeystoreItem item = items[index];

      if (item.type != type) {
        continue;
      }

      ECPublicKey keyPairPublicKey = (ECPublicKey) item.pair.getPublic();

      short comparingLength = keyPairPublicKey.getW(publicKeyWBuffer, (short) 0);

      if (comparingLength == publicKeyLength &&
          Util.arrayCompare(publicKey, publicKeyOffset,
              publicKeyWBuffer, (short) 0,
              publicKeyLength) == 0) {

        return index;
      }
    }

    return -1;
  }

}
