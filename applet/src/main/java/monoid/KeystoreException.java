package monoid;

public class KeystoreException extends MonoidException {
  public static final short REASON_KEY_NOT_FOUND = 1;
  public static final short REASON_INVALID_PARAMETER = 2;

  public static final byte[] CODE_KEY_NOT_FOUND = {
      'K', 'E', 'Y', '_', 'N', 'O', 'T', '_', 'F', 'O', 'U', 'N', 'D' };
  public static final byte[] CODE_INVALID_PARAMETER = {
      'I', 'N', 'V', 'A', 'L', 'I', 'D', '_', 'P', 'A', 'R', 'A', 'M', 'E', 'T', 'E', 'R' };

  public static Object[] codes;

  private static KeystoreException instance;

  public static void init() {
    codes = new Object[] {
        CODE_KEY_NOT_FOUND,
        CODE_INVALID_PARAMETER
    };

    instance = new KeystoreException();
  }

  public static void dispose() {
    codes = null;
    instance = null;
  }

  public static void throwIt(short reason) throws KeystoreException {
    instance.reason = reason;
    instance.code = (byte[]) codes[(short) (reason - 1)];

    throw instance;
  }
}
