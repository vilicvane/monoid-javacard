package monoid;

import static monoid.Constants.SAFE_FALSE;
import static monoid.Constants.SAFE_TRUE;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Shareable;

public class MonoidApplet extends Applet implements Monoid, AppletEvent {

  public static final byte PIN_TRY_LIMIT = 5;
  public static final byte MAX_PIN_LENGTH = 16;

  private static final short PIN_UNSET = (short) 0xA501;
  private static final short PIN_SET = (short) 0x5AFE;

  public static OwnerPIN pin;

  private static short pinState = PIN_UNSET;
  private static short pinStateInverse = (short) ~PIN_UNSET;

  public static Safe safe;

  public static Keystore keystore;

  private static LibSecurity.Condition pinSetValidation;
  private static LibSecurity.Condition pinUpdateAuthorizationRequired;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    MonoidException.init();
    PINException.init();
    SafeException.init();
    KeystoreException.init();
    CurveException.init();
    SignerException.init();

    LibMath.init();
    WeierstrassCurve.init();
    EdwardsCurve.init();
    LibHMACSha512.init();
    KeyDerivation.init();

    Command.init();

    pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_LENGTH);
    pinState = PIN_UNSET;
    pinStateInverse = (short) ~PIN_UNSET;

    pinSetValidation = new LibSecurity.Condition() {
      @Override
      public boolean check() {
        short state = pinState;

        if ((state != PIN_UNSET && state != PIN_SET) || pinStateInverse != (short) ~state) {
          MonoidException.throwIt(MonoidException.CODE_UNAUTHORIZED);
        }

        return state == PIN_SET;
      }
    };
    pinUpdateAuthorizationRequired = new LibSecurity.Condition() {
      @Override
      public boolean check() {
        boolean pinSet = pinSetValidation.check();

        return safe.isPINSet() || pinSet;
      }
    };

    new MonoidApplet().register();
  }

  public void uninstall() {
    MonoidException.dispose();
    PINException.dispose();
    SafeException.dispose();
    KeystoreException.dispose();
    CurveException.dispose();
    SignerException.dispose();

    LibMath.dispose();
    WeierstrassCurve.dispose();
    EdwardsCurve.dispose();
    LibHMACSha512.dispose();
    KeyDerivation.dispose();

    Command.dispose();

    pin = null;

    pinSetValidation = null;
    pinUpdateAuthorizationRequired = null;

    safe = null;

    keystore = null;
  }

  MonoidApplet() {
    safe = new Safe();
  }

  public void process(APDU apdu) {
    if (selectingApplet()) {
      Command.clearTransport();
      return;
    }

    ensureInitialization();

    Command.process(apdu);
  }

  @Override
  public void deselect() {
    super.deselect();

    Command.clearTransport();
  }

  private static void ensureInitialization() {
    safe.initializeIdentity();

    if (keystore == null) {
      keystore = new Keystore(safe);
    }
  }

  public static void checkPINUpdate() throws MonoidException {
    if (LibSecurity.check(pinUpdateAuthorizationRequired, SAFE_TRUE) != SAFE_FALSE) {
      Command.requireAuth(Command.AUTH_SECRET);

      if (safe.getPINValidationResult() != SAFE_TRUE) {
        MonoidException.throwIt(MonoidException.CODE_UNAUTHORIZED);
      }
    } else {
      Command.getAuth();
    }
  }

  static short getPINSetResult(short conservativeResult) {
    return LibSecurity.check(pinSetValidation, conservativeResult);
  }

  static void resetPIN(OwnerPIN replacement) {
    pin = replacement;
    pinState = PIN_UNSET;
    pinStateInverse = (short) ~PIN_UNSET;
  }

  public static void updatePIN(byte[] pinBytes) {
    checkPINUpdate();

    if (safe.getPINSetResult(SAFE_FALSE) != SAFE_TRUE) {
      MonoidException.throwIt(MonoidException.CODE_SECRET_PIN_NOT_SET);
    }

    setPIN(pinBytes);
  }

  public static void updateSecretPIN(byte[] pin) {
    checkPINUpdate();

    safe.updatePIN(pin);

    if (getPINSetResult(SAFE_TRUE) == SAFE_FALSE) {
      setPIN(pin);
    }
  }

  private static void setPIN(byte[] pinBytes) {
    JCSystem.beginTransaction();

    try {
      pin.update(pinBytes, (short) 0, (byte) pinBytes.length);
      pinState = PIN_SET;
      pinStateInverse = (short) ~PIN_SET;

      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }
  }

  @Override
  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    return this;
  }
}
