package tests;

import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import monoidsafe.SafeItemShareable;
import monoidsafe.SafeShareable;

/** A separate applet package exercises the Safe shareable boundary in simulator tests. */
public class SafeCallerApplet extends Applet implements SafeCallerShareable {

  public static final byte GET_SHAREABLE = 1;
  public static final byte UPDATE_PIN = 2;
  public static final byte CHECK_PIN = 3;
  public static final byte CREATE = 4;
  public static final byte LIST = 5;
  public static final byte GET = 6;
  public static final byte GET_DATA = 7;
  public static final byte SET_DATA = 8;
  public static final byte REMOVE = 9;
  public static final byte IS_PIN_VALIDATED = 10;
  public static final byte GET_PIN_TRIES = 11;
  public static final byte CHECK_NULL_PIN = 12;
  public static final byte IS_PIN_SET = 13;
  public static final byte GET_INDEX = 14;
  public static final byte GET_ALIAS = 15;
  public static final byte SET_ALIAS = 16;
  public static final byte BORROW_SAFE = 17;
  public static final byte BORROW_ITEM = 18;

  private static final AID SAFE_AID = AIDUtil.create("f06d6f6e6f696400010000");

  private SafeShareable safe;
  private SafeItemShareable item;

  public static void install(byte[] buffer, short offset, byte length) {
    new SafeCallerApplet().register();
  }

  @Override
  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    byte[] buffer = apdu.getBuffer();
    byte instruction = buffer[ISO7816.OFFSET_INS];
    short length = apdu.setIncomingAndReceive();

    switch (instruction) {
      case GET_SHAREABLE:
        SafeShareable previous = safe;
        safe = (SafeShareable) JCSystem.getAppletShareableInterfaceObject(SAFE_AID, (byte) 0);

        if (safe == null) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        sendBoolean(apdu, safe == previous);
        return;
      case BORROW_SAFE:
      case BORROW_ITEM:
        AID callerAID = JCSystem.lookupAID(buffer, ISO7816.OFFSET_CDATA, (byte) length);
        SafeCallerShareable caller =
          (SafeCallerShareable) JCSystem.getAppletShareableInterfaceObject(callerAID, (byte) 0);

        if (instruction == BORROW_SAFE) {
          safe = caller.getSafe();
        } else {
          item = caller.getItem();
        }

        return;
      case UPDATE_PIN:
        safe.updatePIN(buffer, ISO7816.OFFSET_CDATA, (byte) length);
        return;
      case CHECK_PIN:
        sendBoolean(apdu, safe.checkPIN(buffer, ISO7816.OFFSET_CDATA, (byte) length));
        return;
      case CHECK_NULL_PIN:
        safe.checkPIN(null, (short) 0, (byte) 1);
        return;
      case CREATE:
        item = safe.create(index(), null, duplicate(buffer, ISO7816.OFFSET_CDATA, length));
        sendBoolean(apdu, item != null);
        return;
      case LIST:
        Util.setShort(buffer, (short) 0, (short) safe.list((short) 0).length);
        apdu.setOutgoingAndSend((short) 0, (short) 2);
        return;
      case GET:
        item = safe.get(index());
        sendBoolean(apdu, item != null);
        return;
      case GET_DATA:
        sendBytes(apdu, item.getData());
        return;
      case SET_DATA:
        item.setData(duplicate(buffer, ISO7816.OFFSET_CDATA, length));
        return;
      case GET_INDEX:
        sendBytes(apdu, item.getIndex());
        return;
      case GET_ALIAS:
        sendBytes(apdu, item.getAlias());
        return;
      case SET_ALIAS:
        item.setAlias(duplicate(buffer, ISO7816.OFFSET_CDATA, length));
        return;
      case REMOVE:
        item.remove();
        return;
      case IS_PIN_VALIDATED:
        sendBoolean(apdu, safe.isPINValidated());
        return;
      case GET_PIN_TRIES:
        buffer[0] = safe.getPINTriesRemaining();
        apdu.setOutgoingAndSend((short) 0, (short) 1);
        return;
      case IS_PIN_SET:
        sendBoolean(apdu, safe.isPINSet());
        return;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }

  @Override
  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    return this;
  }

  @Override
  public SafeShareable getSafe() {
    return safe;
  }

  @Override
  public SafeItemShareable getItem() {
    return item;
  }

  private byte[] index() {
    byte[] index = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      SafeShareable.INDEX_LENGTH
    );
    index[0] = 0x10;
    index[index.length - 1] = 1;
    return index;
  }

  private byte[] duplicate(byte[] buffer, short offset, short length) {
    byte[] duplicate = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, length);
    Util.arrayCopyNonAtomic(buffer, offset, duplicate, (short) 0, length);
    return duplicate;
  }

  private void sendBoolean(APDU apdu, boolean value) {
    apdu.getBuffer()[0] = value ? (byte) 1 : 0;
    apdu.setOutgoingAndSend((short) 0, (short) 1);
  }

  private void sendBytes(APDU apdu, byte[] value) {
    if (value != null) {
      Util.arrayCopyNonAtomic(value, (short) 0, apdu.getBuffer(), (short) 0, (short) value.length);
      apdu.setOutgoingAndSend((short) 0, (short) value.length);
    }
  }
}
