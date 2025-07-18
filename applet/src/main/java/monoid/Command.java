package monoid;

import javacard.framework.*;

import monoidsafe.MonoidSafe;
import monoidsafe.MonoidSafeApplet;

public abstract class Command {
  public static final byte AUTH_ACCESS = 0b01;
  public static final byte AUTH_SAFE = 0b10;

  protected static CBORApduReader reader;
  protected static CBORApduWriter writer;

  public static Command hello;
  public static Command setPIN;

  public static void init() {
    reader = new CBORApduReader();
    writer = new CBORApduWriter();

    hello = new CommandHello();
    setPIN = new CommandSetPIN();
  }

  public static void dispose() {
    reader = null;
    writer = null;

    hello = null;
    setPIN = null;
  }

  protected static void sendEmptyMap() {
    writer.map((short) 0);
    writer.send();
  }

  protected static void sendError(byte[] code) {
    writeError(code, (short) 0).send();
  }

  protected static CBORApduWriter writeError(byte[] code, short extra) {
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

  public void runCommand() {
    reader.reset();
    writer.reset();

    try {
      run();
    } catch (MonoidException e) {
      sendError(e.code);
    }
  }

  protected abstract void run() throws MonoidException;

  protected byte getAuth() throws MonoidException {
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
        MonoidException.throwIt(MonoidException.CODE_PIN_NOT_SET);
        return 0;
      }

      if (safe.checkPIN(buffer, (short) 0, length)) {
        return AUTH_SAFE | AUTH_ACCESS;
      }

      tries = safe.getPINTriesRemaining();
    } else {
      if (!MonoidApplet.pinSet) {
        MonoidException.throwIt(MonoidException.CODE_PIN_NOT_SET);
        return 0;
      }

      OwnerPIN pin = MonoidApplet.pin;

      if (pin.check(buffer, (short) 0, length)) {
        return AUTH_ACCESS;
      }

      tries = pin.getTriesRemaining();
    }

    CBORApduWriter writer = writeError(MonoidException.CODE_INVALID_PIN, (short) 1);

    writer.text(Text.tries);
    writer.integer(tries);

    writer.send();

    return 0;
  }

  protected byte requireAuth(byte requiredAuth) throws MonoidException {
    byte auth = getAuth();

    if ((auth & requiredAuth) == 0) {
      MonoidException.throwIt(MonoidException.CODE_UNAUTHORIZED);
      return 0;
    }

    return auth;
  }

  protected byte requireAuth() throws MonoidException {
    return requireAuth((byte) (AUTH_ACCESS | AUTH_SAFE));
  }

  protected void assertAuth(byte auth, byte requiredAuth) throws MonoidException {
    if ((auth & requiredAuth) == 0) {
      MonoidException.throwIt(
          auth == 0 ? MonoidException.CODE_UNAUTHORIZED
              : MonoidException.CODE_ACCESS_DENIED);
    }
  }
}
