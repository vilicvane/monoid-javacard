package monoid;

import javacard.framework.CardRuntimeException;

public class MonoidException extends CardRuntimeException {
  public static final byte[] CODE_ACCESS_DENIED = {
      'A', 'C', 'C', 'E', 'S', 'S', '_', 'D', 'E', 'N', 'I', 'E', 'D' };
  public static final byte[] CODE_INVALID_PARAMETER = {
      'I', 'N', 'V', 'A', 'L', 'I', 'D', '_', 'P', 'A', 'R', 'A', 'M', 'E', 'T', 'E', 'R' };
  public static final byte[] CODE_INVALID_PIN = {
      'I', 'N', 'V', 'A', 'L', 'I', 'D', '_', 'P', 'I', 'N' };
  public static final byte[] CODE_NOT_FOUND = {
      'N', 'O', 'T', '_', 'F', 'O', 'U', 'N', 'D' };
  public static final byte[] CODE_PIN_NOT_SET = {
      'P', 'I', 'N', '_', 'N', 'O', 'T', '_', 'S', 'E', 'T' };
  public static final byte[] CODE_SAFE_BLOCKED = {
      'S', 'A', 'F', 'E', '_', 'B', 'L', 'O', 'C', 'K', 'E', 'D' };
  /**
   * Note this error suggests that safe PIN needs to be set first, it's not a
   * more specific version of PIN_NOT_SET.
   */
  public static final byte[] CODE_SAFE_PIN_NOT_SET = {
      'S', 'A', 'F', 'E', '_', 'P', 'I', 'N', '_', 'N', 'O', 'T', '_', 'S', 'E', 'T' };
  public static final byte[] CODE_SAFE_LOCKED = {
      'S', 'A', 'F', 'E', '_', 'L', 'O', 'C', 'K', 'E', 'D' };
  public static final byte[] CODE_UNAUTHORIZED = {
      'U', 'N', 'A', 'U', 'T', 'H', 'O', 'R', 'I', 'Z', 'E', 'D' };

  private static MonoidException instance;

  public static void init() {
    instance = new MonoidException();
  }

  public static void dispose() {
    instance = null;
  }

  public static void throwIt(byte[] code) throws MonoidException {
    instance.code = code;
    throw instance;
  }

  protected short reason = 0;
  protected byte[] code;

  public MonoidException() {
    super((short) 0);
  }

  public short getReason() {
    return reason;
  }

  public void send() {
    Command.sendError(code);
  }
}
