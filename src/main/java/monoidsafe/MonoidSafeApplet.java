package monoidsafe;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Shareable;
import javacard.security.RandomData;

public class MonoidSafeApplet extends Applet implements SafeShareable {

  public static final byte ID_LENGTH = 4;

  public static final byte PIN_TRY_LIMIT = 5;
  public static final byte MAX_PIN_LENGTH = 16;

  private static final short ITEM_LENGTH_EXTENSION = 8;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new MonoidSafeApplet().register();
  }

  public byte[] id = new byte[ID_LENGTH];

  private OwnerPIN pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_LENGTH);
  private boolean pinSet = false;

  private SafeItem[] items = new SafeItem[ITEM_LENGTH_EXTENSION];

  private short itemsLength = 0;

  MonoidSafeApplet() {
    RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);

    if (random != null) {
      random.nextBytes(id, (short) 0, (short) id.length);
    }
  }

  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
  }

  @Override
  public byte[] getId() {
    return Utils.duplicateAsGlobal(id);
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
  public Object[] list(short type) {
    assertAccess();

    short count = 0;

    for (short index = 0; index < itemsLength; index++) {
      if (items[index].matches(type)) {
        count++;
      }
    }

    Object[] itemShareables = (Object[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_OBJECT,
      count
    );

    short offset = 0;

    for (short index = 0; index < itemsLength; index++) {
      SafeItem item = items[index];

      if (item.matches(type)) {
        itemShareables[offset] = item;

        offset++;
      }
    }

    return itemShareables;
  }

  @Override
  public SafeItemShareable get(byte[] index) {
    assertAccess();

    for (short itemIndex = 0; itemIndex < itemsLength; itemIndex++) {
      SafeItem item = items[itemIndex];

      if (item.matches(index)) {
        return item;
      }
    }

    return null;
  }

  @Override
  public SafeItemShareable create(byte[] index, byte[] alias, byte[] data) {
    assertAccess();

    for (short itemIndex = 0; itemIndex < itemsLength; itemIndex++) {
      if (items[itemIndex].matches(index)) {
        return null;
      }
    }

    JCSystem.beginTransaction();

    if (itemsLength == items.length) {
      SafeItem[] extendedItems = new SafeItem[(short) (items.length + ITEM_LENGTH_EXTENSION)];

      for (short itemIndex = 0; itemIndex < itemsLength; itemIndex++) {
        extendedItems[itemIndex] = items[itemIndex];
      }

      items = extendedItems;

      JCSystem.requestObjectDeletion();
    }

    index = Utils.duplicateAsPersistent(index);

    if (alias != null) {
      alias = Utils.duplicateAsPersistent(alias);
    }

    data = Utils.duplicateAsPersistent(data);

    SafeItem item = new SafeItem(index, alias, data, this);

    items[itemsLength++] = item;

    JCSystem.commitTransaction();

    return item;
  }

  public void remove(SafeItem item) {
    assertAccess();

    short indexToDelete = -1;

    for (short index = 0; index < itemsLength; index++) {
      if (items[index] == item) {
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

    items[itemsLength--] = null;

    JCSystem.requestObjectDeletion();

    JCSystem.commitTransaction();
  }

  public void assertAccess() {
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
}
