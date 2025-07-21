package monoid;

public class SafeException extends MonoidException {

  public static final short REASON_INVALID_PARAMETER = 1;
  public static final short REASON_NOT_FOUND = 2;

  // @formatter:off
  public static final byte[] CODE_INVALID_PARAMETER = {'I','N','V','A','L','I','D','_','P','A','R','A','M','E','T','E','R'};
  public static final byte[] CODE_NOT_FOUND = {'N','O','T','_','F','O','U','N','D'};
  // @formatter:on

  public static Object[] codes;

  private static SafeException instance;

  public static void init() {
    codes = new Object[] { CODE_INVALID_PARAMETER, CODE_NOT_FOUND };

    instance = new SafeException();
  }

  public static void dispose() {
    codes = null;
    instance = null;
  }

  public static void throwIt(short reason) throws SafeException {
    instance.reason = reason;
    instance.code = (byte[]) codes[(short) (reason - 1)];

    throw instance;
  }
}
