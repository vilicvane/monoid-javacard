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

public class MonoidSafeApplet extends Applet {

  public static final byte ID_LENGTH = 4;

  public static final byte PIN_TRY_LIMIT = 5;
  public static final byte MAX_PIN_LENGTH = 16;

  private static final short PIN_UNSET = (short) 0xA501;
  private static final short PIN_SET = (short) 0x5AFE;

  private static final short ITEM_LENGTH_EXTENSION = 8;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new MonoidSafeApplet().register();
  }

  public byte[] id = new byte[ID_LENGTH];

  private OwnerPIN pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_LENGTH);

  private LibSecurity.Condition pinValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return pin.isValidated();
    }
  };

  private short pinState = PIN_UNSET;
  private short pinStateInverse = (short) ~PIN_UNSET;

  private final LibSecurity.Condition pinSetValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      short state = pinState;

      if ((state != PIN_UNSET && state != PIN_SET) || pinStateInverse != (short) ~state) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      return state == PIN_SET;
    }
  };

  private final LibSecurity.Condition pinBlockedValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return pin.getTriesRemaining() == 0;
    }
  };

  private final Object[] callerCheckParameters = JCSystem.makeTransientObjectArray(
    (short) 2,
    JCSystem.CLEAR_ON_RESET
  );

  private final LibSecurity.Condition callerAdmissionValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      AID caller = (AID) callerCheckParameters[0];

      return (
        caller != null &&
        caller.partialEquals(
          Constants.MONOID_AID_WITHOUT_VERSION,
          (short) 0,
          (byte) Constants.MONOID_AID_WITHOUT_VERSION.length
        )
      );
    }
  };

  private final LibSecurity.Condition callerMatchValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      AID caller = (AID) callerCheckParameters[0];
      SafeSession session = (SafeSession) callerCheckParameters[1];

      return session.matches(caller);
    }
  };

  // Only authenticated sessions are retained, and only until reset.
  private Object[] sessions = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);

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

  public byte[] getId() {
    return Utils.duplicateAsGlobal(id);
  }

  public boolean isPINSet() {
    return pinSetValidation.check();
  }

  public byte getPINTriesRemaining() {
    return pin.getTriesRemaining();
  }

  public boolean checkPIN(SafeSession session, byte[] buffer, short offset, byte length) {
    session.assertCaller();

    clearAuth(JCSystem.getPreviousContextAID());
    pin.reset();

    try {
      if (LibSecurity.check(pinSetValidation, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
        return false;
      }

      if (!pin.check(buffer, offset, length)) {
        return false;
      }

      if (LibSecurity.check(pinValidation, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      session.setNext((SafeSession) sessions[0]);
      sessions[0] = session;
      session.setAuth();

      return true;
    } finally {
      if (LibSecurity.check(pinBlockedValidation, Constants.SAFE_TRUE) != Constants.SAFE_FALSE) {
        clearAuth();
      }
    }
  }

  public void updatePIN(SafeSession session, byte[] buffer, short offset, byte length) {
    checkPINUpdate(session);

    JCSystem.beginTransaction();

    try {
      checkPINUpdate(session);
      clearAuth();

      pin.update(buffer, offset, length);
      pinState = PIN_SET;
      pinStateInverse = (short) ~PIN_SET;

      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }
  }

  private void checkPINUpdate(SafeSession session) {
    session.assertCaller();

    if (LibSecurity.check(pinSetValidation, Constants.SAFE_TRUE) != Constants.SAFE_FALSE) {
      assertAccess(session);
    }
  }

  public boolean isPINValidated(SafeSession session) {
    session.assertCaller();

    if (LibSecurity.check(pinSetValidation, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
      return false;
    }

    // The native validated flag describes the last PIN check, not each caller's grant.
    if (session.isAuthorized() != Constants.SAFE_TRUE) {
      return false;
    }

    return LibSecurity.check(pinBlockedValidation, Constants.SAFE_TRUE) == Constants.SAFE_FALSE;
  }

  public Object[] list(SafeSession session, short type) {
    return list(session, type, null);
  }

  public Object[] list(SafeSession session, short type, byte[] dataPrefix) {
    assertAccess(session);

    short count = 0;

    for (short index = 0; index < itemsLength; index++) {
      if (items[index].matches(type, dataPrefix)) {
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

      if (item.matches(type, dataPrefix)) {
        itemShareables[offset] = new SafeSessionItem(session, item);

        offset++;
      }
    }

    return itemShareables;
  }

  public SafeItemShareable get(SafeSession session, byte[] index) {
    assertAccess(session);

    for (short itemIndex = 0; itemIndex < itemsLength; itemIndex++) {
      SafeItem item = items[itemIndex];

      if (item.matches(index)) {
        return new SafeSessionItem(session, item);
      }
    }

    return null;
  }

  public SafeItemShareable create(SafeSession session, byte[] index, byte[] alias, byte[] data) {
    assertAccess(session);

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

    SafeItem item = new SafeItem(index, alias, data);

    items[itemsLength++] = item;

    JCSystem.commitTransaction();

    return new SafeSessionItem(session, item);
  }

  public void remove(SafeSession session, SafeItem item) {
    assertAccess(session);

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

    items[--itemsLength] = null;

    JCSystem.requestObjectDeletion();

    JCSystem.commitTransaction();
  }

  public void assertAccess(SafeSession session) {
    session.assertCaller();

    if (LibSecurity.check(pinSetValidation, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (session.isAuthorized() != Constants.SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (LibSecurity.check(pinBlockedValidation, Constants.SAFE_TRUE) != Constants.SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  private void clearAuth() {
    SafeSession session = (SafeSession) sessions[0];

    while (session != null) {
      SafeSession next = session.getNext();

      session.clearAuth();
      sessions[0] = next;
      session.setNext(null);

      session = next;
    }

    pin.reset();
  }

  private void clearAuth(AID caller) {
    SafeSession previous = null;
    SafeSession session = (SafeSession) sessions[0];

    while (session != null) {
      SafeSession next = session.getNext();

      if (
        checkCaller(callerMatchValidation, caller, session, Constants.SAFE_TRUE) !=
        Constants.SAFE_FALSE
      ) {
        session.clearAuth();

        if (previous == null) {
          sessions[0] = next;
        } else {
          previous.setNext(next);
        }

        session.setNext(null);
      } else {
        previous = session;
      }

      session = next;
    }
  }

  @Override
  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    if (
      checkCaller(callerAdmissionValidation, clientAID, null, Constants.SAFE_FALSE) !=
      Constants.SAFE_TRUE
    ) {
      return null;
    }

    SafeSession session = (SafeSession) sessions[0];

    while (session != null) {
      if (
        checkCaller(callerMatchValidation, clientAID, session, Constants.SAFE_FALSE) ==
        Constants.SAFE_TRUE
      ) {
        return session;
      }

      session = session.getNext();
    }

    return new SafeSession(this, clientAID);
  }

  private short checkCaller(
    LibSecurity.Condition condition,
    AID caller,
    SafeSession session,
    short conservativeResult
  ) {
    callerCheckParameters[0] = caller;
    callerCheckParameters[1] = session;

    try {
      return LibSecurity.check(condition, conservativeResult);
    } finally {
      callerCheckParameters[0] = null;
      callerCheckParameters[1] = null;
    }
  }
}
