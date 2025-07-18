package monoid;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;

import monoidsafe.MonoidSafe;

public class MonoidApplet extends Applet implements Monoid, AppletEvent, ExtendedLength {
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

    // case 0x01:
    //   short publicKeyLength = keystore.genKey(Keystore.TYPE_RAW, buffer, (short) 0);
    //   apdu.setOutgoingAndSend((short) 0, publicKeyLength);
    //   break;
    // case 0x02:
    //   short signatureLength = keystore.sign(
    //       buffer,
    //       ISO7816.OFFSET_CDATA,
    //       (short) (Keystore.SAFE_INDEX_LENGTH + ISO7816.OFFSET_CDATA), (byte) 32,
    //       buffer, (short) 0);
    //   apdu.setOutgoingAndSend((short) 0, signatureLength);
    //   break;
    // case 0x03:
    //   short offset = ISO7816.OFFSET_CDATA;

    //   byte[] key = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);

    //   Util.arrayCopyNonAtomic(buffer, offset, key, (short) 0, (short) 32);

    //   short digestLength = LibHMACSha512.digest(
    //       // key
    //       key, (short) 0, (short) 32,
    //       // data
    //       buffer, (short) (offset + 32), (short) 37,
    //       buffer, (short) 0);

    //   apdu.setOutgoingAndSend((short) 0, digestLength);
    //   break;
    // case 0x04:
    //   byte[] privateKeyAndChainCode = JCSystem.makeTransientByteArray((short) (CurveSECP256k1.KEY_LENGTH * 2),
    //       JCSystem.CLEAR_ON_DESELECT);

    //   short pathOffset = (short) (ISO7816.OFFSET_CDATA
    //       + Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, privateKeyAndChainCode, (short) 0,
    //           (short) (CurveSECP256k1.KEY_LENGTH * 2)));

    //   LibBIP32.deriveChildKey(privateKeyAndChainCode, buffer, pathOffset);

    //   Util.arrayCopyNonAtomic(privateKeyAndChainCode, (short) 0, buffer, (short) 0,
    //       (short) privateKeyAndChainCode.length);

    //   apdu.setOutgoingAndSend((short) 0, (short) privateKeyAndChainCode.length);
    //   break;
    // case 0x05:
    //   short length = safe.get(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC]);
    //   apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, length);
    //   break;

    // ISOException.throwIt(ISO7816.SW_NO_ERROR);
  }

  private static void ensureInitialization() {
    if (version == 0) {
      byte[] buffer = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);

      short length = JCSystem.getAID().getBytes(buffer, (short) 0);

      version = Util.getShort(buffer, (short) (length - 2));
    }

    if (safe == null) {
      safe = (MonoidSafe) JCSystem.getAppletShareableInterfaceObject(
          JCSystem.lookupAID(Constants.MONOID_SAFE_AID, (short) 0, (byte) Constants.MONOID_SAFE_AID.length),
          (byte) 0);

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

    if (JCSystem.isObjectDeletionSupported()) {
      JCSystem.requestObjectDeletion();
    }

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

    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) safePIN.length);

    Util.arrayCopyNonAtomic(safePIN, (short) 0, buffer, (short) 0, (short) safePIN.length);

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
