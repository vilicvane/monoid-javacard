package monoid;

public class CurveException extends MonoidException {
  public static final short REASON_UNSUPPORTED_CURVE = 1;

  public static final byte[] CODE_UNSUPPORTED_CURVE = {
      'U', 'N', 'S', 'U', 'P', 'P', 'O', 'R', 'T', 'E', 'D', '_', 'C', 'U', 'R', 'V', 'E' };

  public static Object[] codes;

  private static CurveException instance;

  public static void init() {
    codes = new Object[] {
        CODE_UNSUPPORTED_CURVE
    };

    instance = new CurveException();
  }

  public static void dispose() {
    codes = null;
    instance = null;
  }

  public static void throwIt(short reason) throws CurveException {
    instance.reason = reason;
    instance.code = (byte[]) codes[(short) (reason - 1)];

    throw instance;
  }
}
