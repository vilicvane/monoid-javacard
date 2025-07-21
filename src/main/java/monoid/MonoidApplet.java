package monoid;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Shareable;
import javacard.framework.Util;
import monoidsafe.MonoidSafe;

public class MonoidApplet extends Applet implements Monoid, AppletEvent {

  public static final byte PIN_TRY_LIMIT = 5;
  public static final byte MAX_PIN_SIZE = 16;

  public static short version = 0;

  public static OwnerPIN pin;
  public static boolean pinSet = false;

  public static Safe safe;

  public static byte[] safePIN;

  public static Keystore keystore;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    MonoidException.init();
    SafeException.init();
    KeystoreException.init();
    CurveException.init();
    SignerException.init();

    CurveSECP256k1.init();
    LibHMACSha512.init();

    Command.init();

    pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

    new MonoidApplet().register();
  }

  public void uninstall() {
    MonoidException.dispose();
    SafeException.dispose();
    KeystoreException.dispose();
    SignerException.dispose();
    CurveException.dispose();

    CurveSECP256k1.dispose();
    LibHMACSha512.dispose();

    Command.dispose();

    pin = null;

    safe = null;
    safePIN = null;

    keystore = null;
  }

  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    ensureInitialization();

    Command command = Command.get(apdu.getBuffer()[ISO7816.OFFSET_INS]);

    if (command == null) {
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      return;
    }

    command.runCommand();
  }

  private static void ensureInitialization() {
    if (version == 0) {
      byte[] buffer = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);

      short length = JCSystem.getAID().getBytes(buffer, (short) 0);

      version = Util.getShort(buffer, (short) (length - 2));
    }

    if (safe == null) {
      MonoidSafe sio = (MonoidSafe) JCSystem.getAppletShareableInterfaceObject(
        JCSystem.lookupAID(
          Constants.MONOID_SAFE_AID,
          (short) 0,
          (byte) Constants.MONOID_SAFE_AID.length
        ),
        (byte) 0
      );

      if (sio == null) {
        ISOException.throwIt(ISO7816.SW_FILE_INVALID);
      }

      safe = new Safe(sio);
    }

    if (keystore == null) {
      keystore = new Keystore(safe);
    }
  }

  public static void updatePIN(byte[] pinBytes) {
    pin.update(pinBytes, (short) 0, (byte) pinBytes.length);
    pinSet = true;
  }

  public static void updateSafePIN(byte[] pin) {
    safe.updatePIN(pin);

    safePIN = Utils.duplicateAsPersistent(pin);
  }

  public static boolean isSafeUnlocked() {
    return safePIN != null;
  }

  public static void checkSafeUnlocked() throws MonoidException {
    if (safePIN == null) {
      MonoidException.throwIt(MonoidException.CODE_SAFE_LOCKED);
      return;
    }

    if (safe.getPINTriesRemaining() == 0) {
      MonoidException.throwIt(MonoidException.CODE_SAFE_BLOCKED);
      return;
    }

    if (!safe.checkPIN(safePIN)) {
      safePIN = null;
      MonoidException.throwIt(MonoidException.CODE_SAFE_LOCKED);
      return;
    }
  }

  @Override
  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    return this;
  }
}
