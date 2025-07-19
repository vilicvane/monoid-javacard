package monoid;

import javacard.framework.*;
import javacard.security.*;

import monoidsafe.MonoidSafe;
import monoidsafe.MonoidSafeApplet;

public abstract class Command {
  public static final byte[] CODE_CRYPTO_EXCEPTION = {
      'C', 'R', 'Y', 'P', 'T', 'O', '_', 'E', 'X', 'C', 'E', 'P', 'T', 'I', 'O', 'N' };

  public static final byte AUTH_ACCESS = 0b01;
  public static final byte AUTH_SAFE = 0b10;

  protected static CBORApduReader reader;
  protected static CBORApduWriter writer;

  public static Command hello;
  public static Command setPIN;
  public static Command systemInformation;

  public static Command list;
  public static Command createRandomKey;

  public static Command viewKey;

  public static void init() {
    reader = new CBORApduReader();
    writer = new CBORApduWriter();

    hello = new CommandHello();
    setPIN = new CommandSetPIN();
    systemInformation = new CommandSystemInformation();

    list = new CommandList();
    createRandomKey = new CommandCreateRandomKey();

    viewKey = new CommandViewKey();
  }

  public static void dispose() {
    reader = null;
    writer = null;

    hello = null;
    setPIN = null;
    systemInformation = null;

    list = null;
    createRandomKey = null;

    viewKey = null;
  }

  public static Command get(byte ins) {
    switch (ins) {
      case 0x20:
        return hello;
      case 0x2F:
        return systemInformation;
      case 0x21:
        return setPIN;
      case 0x30:
        return list;
      case 0x31:
        return createRandomKey;
      case 0x40:
        return viewKey;
      case (byte) 0xC0:
        writer.send();
        return null;
      default:
        return null;
    }
  }

  protected static void writeEmptyMap() {
    writer.map((short) 0);
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
      e.send();
    } catch (CryptoException e) {
      writeError(CODE_CRYPTO_EXCEPTION, (short) 1);
      writer.text(Text.reason);
      writer.integer(e.getReason());
      writer.send();
    } finally {
      if (JCSystem.isObjectDeletionSupported()) {
        JCSystem.requestObjectDeletion();
      }
    }

    // It the code ever reaches here, it means send() hasn't been called (as it
    // throws inside).
    writer.send();
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

    assertAuth(auth, requiredAuth);

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
