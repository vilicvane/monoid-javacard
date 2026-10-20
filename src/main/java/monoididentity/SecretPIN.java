package monoididentity;

import static monoididentity.Constants.SAFE_FALSE;
import static monoididentity.Constants.SAFE_TRUE;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;

public final class SecretPIN {

  public static final byte PIN_TRY_LIMIT = 5;
  public static final byte MAX_PIN_LENGTH = 16;

  private static final short PIN_UNSET = (short) 0xA501;
  private static final short PIN_SET = (short) 0x5AFE;
  private static final short AUTH_SECRET = (short) 0x5AFE;

  private final OwnerPIN pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_LENGTH);

  private short pinState = PIN_UNSET;
  private short pinStateInverse = (short) ~PIN_UNSET;

  private final Object[] caller = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );
  private final short[] auth = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);

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

  private final LibSecurity.Condition pinValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return pin.isValidated();
    }
  };

  private final LibSecurity.Condition pinBlockedValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return pin.getTriesRemaining() == 0;
    }
  };

  private final LibSecurity.Condition authorizationValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      if (auth[0] == 0 && auth[1] == 0) {
        return false;
      }

      if (auth[0] != AUTH_SECRET || auth[1] != (short) ~AUTH_SECRET) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      AID previous = JCSystem.getPreviousContextAID();

      return previous != null && caller[0] == previous && pin.isValidated();
    }
  };

  public boolean isSet() {
    return LibSecurity.check(pinSetValidation, SAFE_FALSE) == SAFE_TRUE;
  }

  public short getTriesRemaining() {
    return pin.getTriesRemaining();
  }

  public boolean check(byte[] value) {
    clearAuth();

    try {
      if (!isSet() || !pin.check(value, (short) 0, (byte) value.length)) {
        return false;
      }

      if (LibSecurity.check(pinValidation, SAFE_FALSE) != SAFE_TRUE) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      caller[0] = JCSystem.getPreviousContextAID();
      auth[1] = (short) ~AUTH_SECRET;
      auth[0] = AUTH_SECRET;

      return getValidationResult() == SAFE_TRUE;
    } finally {
      if (LibSecurity.check(pinBlockedValidation, SAFE_TRUE) != SAFE_FALSE) {
        clearAuth();
      }
    }
  }

  public void update(byte[] value) {
    checkUpdate();
    JCSystem.beginTransaction();

    try {
      checkUpdate();
      clearAuth();
      pin.update(value, (short) 0, (byte) value.length);
      pinState = PIN_SET;
      pinStateInverse = (short) ~PIN_SET;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }
  }

  private void checkUpdate() {
    if (
      LibSecurity.check(pinSetValidation, SAFE_TRUE) != SAFE_FALSE &&
      getValidationResult() != SAFE_TRUE
    ) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  public short getValidationResult() {
    if (!isSet()) {
      return SAFE_FALSE;
    }

    if (LibSecurity.check(authorizationValidation, SAFE_FALSE) != SAFE_TRUE) {
      return SAFE_FALSE;
    }

    return LibSecurity.check(pinBlockedValidation, SAFE_TRUE) == SAFE_FALSE
      ? SAFE_TRUE
      : SAFE_FALSE;
  }

  public void clearAuth() {
    auth[0] = 0;
    auth[1] = 0;
    caller[0] = null;
    pin.reset();
  }
}
