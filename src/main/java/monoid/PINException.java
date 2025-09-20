package monoid;

public class PINException extends MonoidException {

  // @formatter:off
  public static final byte[] CODE_INVALID_PIN = {'I','N','V','A','L','I','D','_','P','I','N'};
  // @formatter:on

  private static PINException instance;

  public short tries;

  public static void init() {
    instance = new PINException();
    instance.code = CODE_INVALID_PIN;
  }

  public static void dispose() {
    instance = null;
  }

  public static void throwIt(short tries) throws PINException {
    instance.tries = tries;

    throw instance;
  }

  @Override
  public void send() {
    CBORApduWriter writer = Command.writeError(MonoidException.CODE_INVALID_PIN, (short) 1);

    writer.text(Text.tries);
    writer.integer(tries);

    writer.send();
  }
}
