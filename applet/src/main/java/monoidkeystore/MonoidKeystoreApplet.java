package monoidkeystore;

import javacard.framework.*;
import javacard.security.*;

public class MonoidKeystoreApplet extends Applet implements MonoidKeystore {
  private static final byte[] INITIAL_PIN = { (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0' };

  private static final short KEY_PAIRS_LENGTH_EXTENSION = 10;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new MonoidKeystoreApplet();
  }

  private OwnerPIN pin;

  private byte[] keyPairTypes = new byte[KEY_PAIRS_LENGTH_EXTENSION];
  private KeyPair[] keyPairs = new KeyPair[KEY_PAIRS_LENGTH_EXTENSION];

  private short keyPairsLength = 0;

  public MonoidKeystoreApplet() {
    pin = new OwnerPIN((byte) 10, (byte) 32);

    pin.update(INITIAL_PIN, (short) 0, (byte) INITIAL_PIN.length);

    register();
  }

  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
  }

  @Override
  public void verifyPIN(byte[] buffer, short offset, byte length) {
    if (!pin.check(buffer, offset, length)) {
      ISOException.throwIt((short) (0x63C0 | pin.getTriesRemaining()));
    }
  }

  @Override
  public void updatePIN(byte[] buffer, short offset, byte length) {
    assertPINValidated();
    pin.update(buffer, offset, length);
  }

  @Override
  public byte[] getKeyPairTypes() {
    assertPINValidated();
    return keyPairTypes;
  }

  @Override
  public KeyPair[] getKeyPairs() {
    assertPINValidated();
    return keyPairs;
  }

  @Override
  public short getKeyPairsLength() {
    assertPINValidated();
    return keyPairsLength;
  }

  @Override
  public void pushKeyPair(byte type, KeyPair pair) {
    assertPINValidated();

    if (keyPairsLength == keyPairs.length) {
      extendKeyPairs();
    }

    JCSystem.beginTransaction();

    keyPairs[keyPairsLength] = pair;
    keyPairsLength++;

    JCSystem.commitTransaction();
  }

  @Override
  public void removeKeyPair(KeyPair pair) {
    assertPINValidated();

    short indexToRemove = -1;

    for (short index = 0; index < keyPairsLength; index++) {
      if (keyPairs[index] == pair) {
        indexToRemove = index;
        break;
      }
    }

    if (indexToRemove < 0) {
      return;
    }

    JCSystem.beginTransaction();

    for (short index = indexToRemove; index < (short) (keyPairsLength - 1); index++) {
      keyPairTypes[index] = keyPairTypes[(short) (index + 1)];
      keyPairs[index] = keyPairs[(short) (index + 1)];
    }

    keyPairTypes[keyPairsLength] = (byte) 0;
    keyPairs[keyPairsLength] = null;

    keyPairsLength--;

    JCSystem.commitTransaction();

    if (JCSystem.isObjectDeletionSupported()) {
      JCSystem.requestObjectDeletion();
    }
  }

  private void extendKeyPairs() {
    assertPINValidated();

    JCSystem.beginTransaction();

    byte[] extendedKeyPairTypes = new byte[(short) (keyPairTypes.length + KEY_PAIRS_LENGTH_EXTENSION)];
    KeyPair[] extendedKeyPairs = new KeyPair[(short) (keyPairs.length + KEY_PAIRS_LENGTH_EXTENSION)];

    for (short index = 0; index < keyPairsLength; index++) {
      extendedKeyPairTypes[index] = keyPairTypes[index];
      extendedKeyPairs[index] = keyPairs[index];
    }

    keyPairTypes = extendedKeyPairTypes;
    keyPairs = extendedKeyPairs;

    JCSystem.commitTransaction();

    if (JCSystem.isObjectDeletionSupported()) {
      JCSystem.requestObjectDeletion();
    }
  }

  private void assertPINValidated() {
    if (!pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  @Override
  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    if (clientAID.equals(Constants.MONOID_AID, (short) 0, (byte) Constants.MONOID_AID.length)) {
      return this;
    }

    return null;
  }
}
