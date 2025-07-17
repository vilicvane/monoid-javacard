package monoid;

import javacard.framework.*;

import monoidsafe.MonoidSafe;
import monoidsafe.MonoidSafeApplet;

public abstract class Command {
  public static final byte AUTH_NONE = 0b00;
  public static final byte AUTH_ACCESS = 0b01;
  public static final byte AUTH_SAFE = 0b10;

  protected static byte getAuth() {
    ApduCBORReader reader = MonoidApplet.apduReader;

    reader.snapshot();

    reader.map();

    if (!reader.key(Text.auth)) {
      reader.restore();
      return AUTH_NONE;
    }

    reader.map();

    reader.requireKey(Text.safe);

    boolean safeAuth = reader.bool();

    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(
        JCSystem.ARRAY_TYPE_BYTE,
        safeAuth ? MonoidSafeApplet.MAX_PIN_SIZE : MonoidApplet.MAX_PIN_SIZE);

    reader.requireKey(Text.pin);
    byte length = (byte) reader.text(buffer);

    reader.restore();

    short tries;

    if (safeAuth) {
      MonoidSafe safe = MonoidApplet.safe;

      if (!safe.isPINSet()) {
        sendError(ErrorCode.PIN_NOT_SET);
        return AUTH_NONE;
      }

      if (safe.checkPIN(buffer, (short) 0, length)) {
        return AUTH_SAFE | AUTH_ACCESS;
      }

      tries = safe.getPINTriesRemaining();
    } else {
      if (!MonoidApplet.pinSet) {
        sendError(ErrorCode.PIN_NOT_SET);
        return AUTH_NONE;
      }

      OwnerPIN pin = MonoidApplet.pin;

      if (pin.check(buffer, (short) 0, length)) {
        return AUTH_ACCESS;
      }

      tries = pin.getTriesRemaining();
    }

    ApduCBORWriter writer = writeError(ErrorCode.INVALID_PIN, (short) 1);

    writer.text(Text.tries);
    writer.integer(tries);

    writer.send();

    return AUTH_NONE;
  }

  protected static byte requireAuth(byte requiredAuth) {
    byte auth = getAuth();

    if ((auth & requiredAuth) == 0) {
      sendError(ErrorCode.UNAUTHORIZED);
      return AUTH_NONE;
    }

    return auth;
  }

  protected static byte requireAuth() {
    return requireAuth((byte) (AUTH_ACCESS | AUTH_SAFE));
  }

  protected static void assertAuth(byte auth, byte requiredAuth) {
    if ((auth & requiredAuth) == 0) {
      sendError(ErrorCode.UNAUTHORIZED);
    }
  }

  protected static void writeEmptyMap() {
    ApduCBORWriter writer = MonoidApplet.apduWriter;

    writer.map((short) 0);
    writer.send();
  }

  protected static ApduCBORWriter writeError(byte[] code, short extra) {
    ApduCBORWriter writer = MonoidApplet.apduWriter;

    writer.map((short) 1);
    {
      writer.text(Text.error);
      writer.map((short) (1 + extra));
      {
        writer.text(Text.code);
        writer.text(code);
      }
    }

    return writer;
  }

  protected static ApduCBORWriter writeError(byte[] code) {
    return writeError(code, (short) 0);
  }

  protected static void sendError(byte[] code) {
    writeError(code).send();
  }
}
