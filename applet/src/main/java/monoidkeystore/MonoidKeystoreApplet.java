package monoidkeystore;

import javacard.framework.*;
import monoid.MonoidApplet;

public class MonoidKeystoreApplet extends Applet implements MonoidKeystore {
  private static final byte[] INITIAL_PIN = { (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0' };

  private static final short KEY_PAIRS_LENGTH_EXTENSION = 10;

  private static AID aid;

  public static AID getAID() {
    return aid;
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new MonoidKeystoreApplet();
  }

  private OwnerPIN pin;

  private MonoidKeystoreItem[] items = new MonoidKeystoreItem[KEY_PAIRS_LENGTH_EXTENSION];

  private short itemsLength = 0;

  public MonoidKeystoreApplet() {
    pin = new OwnerPIN((byte) 10, (byte) 32);

    pin.update(INITIAL_PIN, (short) 0, (byte) INITIAL_PIN.length);

    register();
  }

  public void process(APDU apdu) {
    if (aid == null) {
      aid = JCSystem.getAID();
    }

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
  public MonoidKeystoreItem[] getItems() {
    assertPINValidated();
    return items;
  }

  @Override
  public short getItemsLength() {
    assertPINValidated();
    return itemsLength;
  }

  @Override
  public void setItemsLength(short length) {
    assertPINValidated();
    itemsLength = length;
  }

  @Override
  public void extendItems() {
    assertPINValidated();

    MonoidKeystoreItem[] extendedItems = new MonoidKeystoreItem[items.length + KEY_PAIRS_LENGTH_EXTENSION];

    for (short index = 0; index < itemsLength; index++) {
      extendedItems[index] = items[index];
    }

    items = extendedItems;

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
    if (clientAID.equals(MonoidApplet.getAID())) {
      return this;
    }

    return null;
  }

}
