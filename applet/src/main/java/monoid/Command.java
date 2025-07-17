package monoid;

import javacard.framework.*;

import monoidsafe.MonoidSafe;
import monoidsafe.MonoidSafeApplet;

public abstract class Command {
  public static final byte AUTH_ACCESS = 0b01;
  public static final byte AUTH_SAFE = 0b10;

  protected static byte getAuth() {
    ApduCBORReader reader = MonoidApplet.apduReader;

    reader.snapshot();

    reader.map();

    if (!reader.key(Text.auth)) {
      reader.restore();
      return 0;
    }

    reader.map();

    boolean safeAuth = reader.key(Text.safe) && reader.boolTrue();

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
        return 0;
      }

      if (safe.checkPIN(buffer, (short) 0, length)) {
        return AUTH_SAFE | AUTH_ACCESS;
      }

      tries = safe.getPINTriesRemaining();
    } else {
      if (!MonoidApplet.pinSet) {
        sendError(ErrorCode.PIN_NOT_SET);
        return 0;
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

    return 0;
  }

  protected static byte requireAuth(byte requiredAuth) {
    byte auth = getAuth();

    if ((auth & requiredAuth) == 0) {
      sendError(ErrorCode.UNAUTHORIZED);
      return 0;
    }

    return auth;
  }

  protected static byte requireAuth() {
    return requireAuth((byte) (AUTH_ACCESS | AUTH_SAFE));
  }

  protected static void assertAuth(byte auth, byte requiredAuth) {
    if ((auth & requiredAuth) == 0) {
      sendError(auth == 0 ? ErrorCode.UNAUTHORIZED : ErrorCode.ACCESS_DENIED);
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
