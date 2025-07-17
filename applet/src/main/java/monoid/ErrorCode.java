package monoid;

public final class ErrorCode {
  public static final byte[] UNAUTHORIZED = {
      'U', 'N', 'A', 'U', 'T', 'H', 'O', 'R', 'I', 'Z', 'E', 'D' };
  public static final byte[] ACCESS_DENIED = {
      'A', 'C', 'C', 'E', 'S', 'S', '_', 'D', 'E', 'N', 'I', 'E', 'D' };
  public static final byte[] INVALID_PIN = {
      'I', 'N', 'V', 'A', 'L', 'I', 'D', '_', 'P', 'I', 'N' };
  public static final byte[] PIN_NOT_SET = {
      'P', 'I', 'N', '_', 'N', 'O', 'T', '_', 'S', 'E', 'T' };
  /**
   * Note this error suggests that safe PIN needs to be set first, it's not a
   * more specific version of PIN_NOT_SET.
   */
  public static final byte[] SAFE_PIN_NOT_SET = {
      'S', 'A', 'F', 'E', '_', 'P', 'I', 'N', '_', 'N', 'O', 'T', '_', 'S', 'E', 'T' };
  public static final byte[] SAFE_LOCKED = {
      'S', 'A', 'F', 'E', '_', 'L', 'O', 'C', 'K', 'E', 'D' };
  public static final byte[] SAFE_BLOCKED = {
      'S', 'A', 'F', 'E', '_', 'B', 'L', 'O', 'C', 'K', 'E', 'D' };
}
