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
import monoidsafeidentity.SafeIdentityShareable;

public class MonoidSafeApplet extends Applet {

  public static final byte PIN_TRY_LIMIT = 5;
  public static final byte MAX_PIN_LENGTH = 16;

  private static final short PIN_UNSET = (short) 0xA501;
  private static final short PIN_SET = (short) 0x5AFE;

  private static final short ITEM_LENGTH_EXTENSION = 8;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new MonoidSafeApplet().register();
  }

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

  private ItemCipher itemCipher;

  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
  }

  public byte[] getId() {
    return requireIdentity().getId();
  }

  public byte[] getPublicKey() {
    return requireIdentity().getPublicKey();
  }

  private SafeIdentityShareable requireIdentity() {
    AID identityAID = JCSystem.lookupAID(
      Constants.MONOID_SAFE_IDENTITY_AID,
      (short) 0,
      (byte) Constants.MONOID_SAFE_IDENTITY_AID.length
    );
    SafeIdentityShareable identity = identityAID == null
      ? null
      : (SafeIdentityShareable) JCSystem.getAppletShareableInterfaceObject(identityAID, (byte) 0);

    if (identity == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    return identity;
  }

  private ItemCipher requireItemCipher() {
    if (itemCipher == null) {
      itemCipher = new ItemCipher();
    }

    return itemCipher;
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

  public SafeItemIteratorShareable list(SafeSession session, short type) {
    return list(session, type, null);
  }

  public SafeItemIteratorShareable list(SafeSession session, short type, byte[] keyPrefix) {
    assertAccess(session);
    return new SafeSessionItemIterator(session, items, itemsLength, type, keyPrefix);
  }

  public SafeItemShareable get(SafeSession session, byte[] index) {
    assertAccess(session);
    SafeItem item = getItem(index);

    return item != null ? new SafeSessionItem(session, item) : null;
  }

  private SafeItem getItem(byte[] index) {
    for (short itemIndex = 0; itemIndex < itemsLength; itemIndex++) {
      SafeItem item = items[itemIndex];

      if (item.matches(index)) {
        return item;
      }
    }

    return null;
  }

  public SafeItemShareable create(
    SafeSession session,
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] data,
    boolean secret
  ) {
    assertAccess(session);

    if (getItem(index) != null) {
      return null;
    }

    SafeItem item = createItem(index, key, alias, data, (short) 0, (short) data.length, secret);

    return new SafeSessionItem(session, item);
  }

  private SafeItem createItem(
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] data,
    short dataOffset,
    short dataLength,
    boolean secret
  ) {
    index = Utils.duplicateAsPersistent(index);
    key = key != null ? Utils.duplicateAsPersistent(key) : null;
    alias = alias != null ? Utils.duplicateAsPersistent(alias) : null;
    data = Utils.duplicateAsPersistent(data, dataOffset, dataLength);

    SafeItem item = new SafeItem(index, key, alias, data, secret);
    SafeItem[] updatedItems = items;

    if (itemsLength == items.length) {
      updatedItems = new SafeItem[(short) (items.length + ITEM_LENGTH_EXTENSION)];

      for (short itemIndex = 0; itemIndex < itemsLength; itemIndex++) {
        updatedItems[itemIndex] = items[itemIndex];
      }
    }

    boolean extended = updatedItems != items;

    JCSystem.beginTransaction();

    try {
      items = updatedItems;
      items[itemsLength++] = item;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }

    if (extended) {
      JCSystem.requestObjectDeletion();
    }

    return item;
  }

  public byte[] exportItem(SafeSession session, SafeItem item, byte[] recipientPublicKey) {
    assertAccess(session);
    return requireItemCipher().encrypt(requireIdentity(), item, recipientPublicKey);
  }

  public void importItem(
    SafeSession session,
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] senderPublicKey,
    byte[] data
  ) {
    assertAccess(session);

    byte[] plaintext = requireItemCipher().decrypt(
      requireIdentity(),
      index,
      key,
      alias,
      senderPublicKey,
      data
    );
    short secret = Util.getShort(plaintext, (short) 0);

    if (secret != Constants.SAFE_TRUE && secret != Constants.SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    short dataLength = (short) (plaintext.length - ItemCipher.SECRET_LENGTH);
    SafeItem item = getItem(index);

    if (item != null) {
      if (
        item.secret != secret ||
        !equal(item.key, key) ||
        !equal(item.alias, alias) ||
        item.data.length != dataLength ||
        Util.arrayCompare(item.data, (short) 0, plaintext, ItemCipher.SECRET_LENGTH, dataLength) !=
        0
      ) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }

      return;
    }

    createItem(
      index,
      key,
      alias,
      plaintext,
      ItemCipher.SECRET_LENGTH,
      dataLength,
      secret == Constants.SAFE_TRUE
    );
  }

  private static boolean equal(byte[] left, byte[] right) {
    return (
      left == right ||
      (left != null &&
        right != null &&
        left.length == right.length &&
        Util.arrayCompare(left, (short) 0, right, (short) 0, (short) left.length) == 0)
    );
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
