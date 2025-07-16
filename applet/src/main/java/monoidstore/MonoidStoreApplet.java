package monoidstore;

import javacard.framework.*;

public class MonoidStoreApplet extends Applet implements MonoidStore {
  private static final byte[] INITIAL_PIN = { (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0' };

  private static final short ITEM_LENGTH_EXTENSION = 8;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new MonoidStoreApplet().register();
  }

  private OwnerPIN pin;

  private Item[] items = new Item[ITEM_LENGTH_EXTENSION];

  private short itemsLength = 0;

  public MonoidStoreApplet() {
    pin = new OwnerPIN((byte) 10, (byte) 32);

    pin.update(INITIAL_PIN, (short) 0, (byte) INITIAL_PIN.length);
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
  public boolean exists(byte[] buffer, short offset, byte indexLength) {
    assertPINValidated();

    for (short index = 0; index < itemsLength; index++) {
      if (items[index].matches(buffer, offset, indexLength)) {
        return true;
      }
    }

    return false;
  }

  @Override
  public short get(byte[] buffer, short offset, byte indexLength) {
    assertPINValidated();

    for (short index = 0; index < itemsLength; index++) {
      Item item = items[index];

      if (item.matches(buffer, offset, indexLength)) {
        Util.arrayCopyNonAtomic(item.data, indexLength, buffer, (short) (offset + indexLength),
            (short) (item.data.length - indexLength));

        return (short) item.data.length;
      }
    }

    return 0;
  }

  @Override
  public void set(byte[] buffer, short offset, byte indexLength, short length) {
    assertPINValidated();

    for (short index = 0; index < itemsLength; index++) {
      Item item = items[index];

      if (item.matches(buffer, offset, indexLength)) {
        JCSystem.beginTransaction();

        item.data = new byte[length];

        Util.arrayCopyNonAtomic(buffer, offset, item.data, (short) 0, length);

        requestObjectDeletion();

        JCSystem.commitTransaction();

        return;
      }
    }

    JCSystem.beginTransaction();

    if (itemsLength == items.length) {

      Item[] extendedItems = new Item[(short) (items.length + ITEM_LENGTH_EXTENSION)];

      for (short index = 0; index < itemsLength; index++) {
        extendedItems[index] = items[index];
      }

      items = extendedItems;

      requestObjectDeletion();
    }

    Item item = new Item();

    item.data = new byte[length];

    Util.arrayCopyNonAtomic(buffer, offset, item.data, (short) 0, length);

    items[itemsLength] = item;

    itemsLength++;

    JCSystem.commitTransaction();
  }

  @Override
  public void delete(byte[] buffer, short offset, byte indexLength) {
    assertPINValidated();

    short indexToDelete = -1;

    for (short index = 0; index < itemsLength; index++) {
      Item item = items[index];

      if (item.matches(buffer, offset, indexLength)) {
        indexToDelete = index;
        break;
      }
    }

    if (indexToDelete < 0) {
      return;
    }

    JCSystem.beginTransaction();

    for (short index = indexToDelete; index < (short) (itemsLength - 1); index++) {
      items[index] = items[(short) (index + 1)];
    }

    items[itemsLength] = null;

    itemsLength--;

    requestObjectDeletion();

    JCSystem.commitTransaction();
  }

  private void requestObjectDeletion() {
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
    if (clientAID.partialEquals(Constants.MONOID_PARTIAL_AID, (short) 0, (byte) Constants.MONOID_PARTIAL_AID.length)) {
      return this;
    }

    return null;
  }

  private class Item {
    public byte[] data;

    public boolean matches(byte[] buffer, short offset, byte indexLength) {
      return data.length > indexLength && Util.arrayCompare(data, (short) 0, buffer, offset, indexLength) == 0;
    }
  }
}
