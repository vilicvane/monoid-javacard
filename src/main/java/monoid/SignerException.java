package monoid;

public class SignerException extends MonoidException {

  public static final short REASON_UNSUPPORTED_CIPHER = 1;

  // @formatter:off
  public static final byte[] CODE_UNSUPPORTED_CIPHER = {'U','N','S','U','P','P','O','R','T','E','D','_','C','I','P','H','E','R'};
  // @formatter:on

  public static Object[] codes;

  private static SignerException instance;

  public static void init() {
    codes = new Object[] { CODE_UNSUPPORTED_CIPHER };

    instance = new SignerException();
  }

  public static void dispose() {
    codes = null;
    instance = null;
  }

  public static void throwIt(short reason) throws SignerException {
    instance.reason = reason;
    instance.code = (byte[]) codes[(short) (reason - 1)];

    throw instance;
  }
}
