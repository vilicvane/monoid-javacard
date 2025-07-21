package monoidsafe;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Shareable;
import javacard.framework.Util;

public class MonoidSafeApplet extends Applet implements MonoidSafe {

  public static final byte PIN_TRY_LIMIT = 5;
  public static final byte MAX_PIN_SIZE = 16;

  private static final short ITEM_LENGTH_EXTENSION = 8;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new MonoidSafeApplet().register();
  }

  private OwnerPIN pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
  private boolean pinSet = false;

  private Item[] items = new Item[ITEM_LENGTH_EXTENSION];

  private short itemsLength = 0;

  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
  }

  @Override
  public boolean isPINSet() {
    return pinSet;
  }

  @Override
  public byte getPINTriesRemaining() {
    return pin.getTriesRemaining();
  }

  @Override
  public boolean checkPIN(byte[] buffer, short offset, byte length) {
    return pin.check(buffer, offset, length);
  }

  @Override
  public void updatePIN(byte[] buffer, short offset, byte length) {
    assertAccess();

    pin.update(buffer, offset, length);
    pinSet = true;
  }

  @Override
  public boolean isPINValidated() {
    return pin.isValidated();
  }

  @Override
  public byte[] list(short type) {
    assertAccess();

    short count = 0;

    for (short index = 0; index < itemsLength; index++) {
      if (items[index].matches(type)) {
        count++;
      }
    }

    byte[] data = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      (short) (INDEX_LENGTH * count)
    );

    short offset = 0;

    for (short index = 0; index < itemsLength; index++) {
      Item item = items[index];

      if (item.matches(type)) {
        offset = Util.arrayCopyNonAtomic(item.data, (short) 0, data, offset, INDEX_LENGTH);
      }
    }

    return data;
  }

  @Override
  public byte[] get(byte[] buffer, short offset) {
    assertAccess();

    for (short index = 0; index < itemsLength; index++) {
      Item item = items[index];

      if (item.matches(buffer, offset)) {
        short length = (short) (item.data.length - INDEX_LENGTH);

        byte[] data = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, length);

        Util.arrayCopyNonAtomic(item.data, INDEX_LENGTH, data, (short) 0, length);

        return data;
      }
    }

    return null;
  }

  @Override
  public boolean set(byte[] buffer, short offset, short length) {
    assertAccess();

    for (short index = 0; index < itemsLength; index++) {
      Item item = items[index];

      if (item.matches(buffer, offset)) {
        JCSystem.beginTransaction();

        item.data = new byte[length];

        Util.arrayCopyNonAtomic(buffer, offset, item.data, (short) 0, length);

        JCSystem.requestObjectDeletion();

        JCSystem.commitTransaction();

        return true;
      }
    }

    JCSystem.beginTransaction();

    if (itemsLength == items.length) {
      Item[] extendedItems = new Item[(short) (items.length + ITEM_LENGTH_EXTENSION)];

      for (short index = 0; index < itemsLength; index++) {
        extendedItems[index] = items[index];
      }

      items = extendedItems;

      JCSystem.requestObjectDeletion();
    }

    Item item = new Item();

    item.data = new byte[length];

    Util.arrayCopyNonAtomic(buffer, offset, item.data, (short) 0, length);

    items[itemsLength] = item;

    itemsLength++;

    JCSystem.commitTransaction();

    return false;
  }

  @Override
  public boolean remove(byte[] buffer, short offset) {
    assertAccess();

    short indexToDelete = -1;

    for (short index = 0; index < itemsLength; index++) {
      Item item = items[index];

      if (item.matches(buffer, offset)) {
        indexToDelete = index;
        break;
      }
    }

    if (indexToDelete < 0) {
      return false;
    }

    JCSystem.beginTransaction();

    for (short index = indexToDelete; index < (short) (itemsLength - 1); index++) {
      items[index] = items[(short) (index + 1)];
    }

    items[itemsLength] = null;

    itemsLength--;

    JCSystem.requestObjectDeletion();

    JCSystem.commitTransaction();

    return true;
  }

  private void assertAccess() {
    if (pinSet && !pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  @Override
  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    if (
      clientAID.partialEquals(
        Constants.MONOID_AID_WITHOUT_VERSION,
        (short) 0,
        (byte) Constants.MONOID_AID_WITHOUT_VERSION.length
      )
    ) {
      return this;
    }

    return null;
  }

  private class Item {

    public byte[] data;

    public boolean matches(byte[] buffer, short offset) {
      return Util.arrayCompare(data, INDEX_OFFSET, buffer, offset, INDEX_LENGTH) == 0;
    }

    public boolean matches(short type) {
      byte high = (byte) (type >> 8);
      byte low = (byte) (type & 0xFF);

      if (low == 0) {
        if (high == 0) {
          return true;
        } else {
          return high == data[INDEX_TYPE_CATEGORY_OFFSET];
        }
      } else {
        return high == data[INDEX_TYPE_CATEGORY_OFFSET] && low == data[INDEX_TYPE_METADATA_OFFSET];
      }
    }
  }
}
