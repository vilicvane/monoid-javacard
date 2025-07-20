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

  public static MonoidSafe safe;
  public static byte[] safePIN;

  public static Keystore keystore;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    MonoidException.init();
    CurveException.init();
    KeystoreException.init();
    SignerException.init();

    CurveSECP256k1.init();
    LibHMACSha512.init();

    Command.init();

    pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

    new MonoidApplet().register();
  }

  public void uninstall() {
    MonoidException.dispose();
    CurveException.dispose();
    KeystoreException.dispose();
    SignerException.dispose();

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
      byte[] buffer = JCSystem.makeTransientByteArray(
        (short) 16,
        JCSystem.CLEAR_ON_DESELECT
      );

      short length = JCSystem.getAID().getBytes(buffer, (short) 0);

      version = Util.getShort(buffer, (short) (length - 2));
    }

    if (safe == null) {
      safe = (MonoidSafe) JCSystem.getAppletShareableInterfaceObject(
        JCSystem.lookupAID(
          Constants.MONOID_SAFE_AID,
          (short) 0,
          (byte) Constants.MONOID_SAFE_AID.length
        ),
        (byte) 0
      );

      if (safe == null) {
        ISOException.throwIt(ISO7816.SW_FILE_INVALID);
      }
    }

    if (keystore == null) {
      keystore = new Keystore(safe);
    }
  }

  public static void updatePIN(byte[] in, short pinOffset, byte pinLength) {
    pin.update(in, pinOffset, pinLength);
    pinSet = true;
  }

  public static void updateSafePIN(byte[] in, short pinOffset, byte pinLength) {
    safe.updatePIN(in, pinOffset, pinLength);

    JCSystem.beginTransaction();

    safePIN = new byte[pinLength];
    Util.arrayCopyNonAtomic(in, pinOffset, safePIN, (short) 0, pinLength);

    JCSystem.commitTransaction();
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

    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      (short) safePIN.length
    );

    Util.arrayCopyNonAtomic(
      safePIN,
      (short) 0,
      buffer,
      (short) 0,
      (short) safePIN.length
    );

    if (!safe.checkPIN(buffer, (short) 0, (byte) safePIN.length)) {
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
