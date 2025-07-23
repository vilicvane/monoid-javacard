package monoid;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;

public abstract class Command {

  // @formatter:off
  public static final byte[] CODE_INTERNAL = {'I','N','T','E','R','N','A','L'};

  public static final byte[] EXCEPTION_CryptoException = {'C','r','y','p','t','o','E','x','c','e','p','t','i','o','n'};
  public static final byte[] EXCEPTION_SecurityException = {'S','e','c','u','r','i','t','y','E','x','c','e','p','t','i','o','n'};
  public static final byte[] EXCEPTION_IndexOutOfBoundsException = {'I','n','d','e','x','O','u','t','O','f','B','o','u','n','d','s','E','x','c','e','p','t','i','o','n'};
  // @formatter:on

  public static final byte AUTH_ACCESS = 0b01;
  public static final byte AUTH_SAFE = 0b10;

  protected static CBORApduReader reader;
  protected static CBORApduWriter writer;

  public static Command hello;
  public static Command setPIN;
  public static Command systemInformation;

  public static Command list;
  public static Command view;
  public static Command get;
  public static Command set;
  public static Command create;
  public static Command remove;
  public static Command createRandomKey;

  public static Command viewKey;
  public static Command sign;

  public static void init() {
    reader = new CBORApduReader();
    writer = new CBORApduWriter();

    hello = new CommandHello();
    setPIN = new CommandSetPIN();
    systemInformation = new CommandSystemInformation();

    list = new CommandList();
    view = new CommandView();
    get = new CommandGet();
    set = new CommandSet();
    create = new CommandCreate();
    remove = new CommandRemove();
    createRandomKey = new CommandCreateRandomKey();

    viewKey = new CommandViewKey();
    sign = new CommandSign();
  }

  public static void dispose() {
    reader = null;
    writer = null;

    hello = null;
    setPIN = null;
    systemInformation = null;

    list = null;
    view = null;
    get = null;
    set = null;
    create = null;
    remove = null;
    createRandomKey = null;

    viewKey = null;
    sign = null;
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
        return view;
      case 0x32:
        return get;
      case 0x33:
        return set;
      case 0x34:
        return create;
      case 0x35:
        return remove;
      case 0x38:
        return createRandomKey;
      case 0x40:
        return viewKey;
      case 0x41:
        return sign;
      case (byte) 0xC0:
        writer.send();
        return null;
      default:
        return null;
    }
  }

  protected static void sendEmptyMap() {
    writer.reset();
    writer.map((short) 0);
    writer.send();
  }

  protected static void sendError(byte[] code) {
    writeError(code, (short) 0).send();
  }

  protected static CBORApduWriter writeError(byte[] code, short extra) {
    writer.reset();

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
    } catch (ISOException e) {
      return;
    } catch (MonoidException e) {
      e.send();
    } catch (CryptoException e) {
      writeError(CODE_INTERNAL, (short) 2);
      {
        writer.text(Text.exception);
        writer.text(EXCEPTION_CryptoException);

        writer.text(Text.reason);
        writer.integer(e.getReason());
      }
      writer.send();
    } catch (SecurityException e) {
      writeError(CODE_INTERNAL, (short) 1);
      {
        writer.text(Text.exception);
        writer.text(EXCEPTION_SecurityException);
      }
      writer.send();
    } catch (IndexOutOfBoundsException e) {
      writeError(CODE_INTERNAL, (short) 1);
      {
        writer.text(Text.exception);
        writer.text(EXCEPTION_IndexOutOfBoundsException);
      }
      writer.send();
    } catch (Exception e) {
      sendError(CODE_INTERNAL);
    } finally {
      JCSystem.requestObjectDeletion();
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

    byte[] pin = Utils.duplicateAsGlobal(reader.requireKey(Text.pin).text());

    reader.restore();

    short tries;

    if (safeAuth) {
      Safe safe = MonoidApplet.safe;

      if (!safe.isPINSet()) {
        MonoidException.throwIt(MonoidException.CODE_PIN_NOT_SET);
        return 0;
      }

      if (safe.checkPIN(pin)) {
        return AUTH_SAFE | AUTH_ACCESS;
      }

      tries = safe.getPINTriesRemaining();
    } else {
      if (!MonoidApplet.pinSet) {
        MonoidException.throwIt(MonoidException.CODE_PIN_NOT_SET);
        return 0;
      }

      if (MonoidApplet.pin.check(pin, (short) 0, (byte) pin.length)) {
        return AUTH_ACCESS;
      }

      tries = MonoidApplet.pin.getTriesRemaining();
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
        auth == 0 ? MonoidException.CODE_UNAUTHORIZED : MonoidException.CODE_ACCESS_DENIED
      );
    }
  }
}
