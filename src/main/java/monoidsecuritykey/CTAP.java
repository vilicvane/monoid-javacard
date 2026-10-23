package monoidsecuritykey;

public final class CTAP {

  public static final short INVALID_COMMAND = 0x01;
  public static final short INVALID_PARAMETER = 0x02;
  public static final short INVALID_LENGTH = 0x03;
  public static final short CBOR_UNEXPECTED_TYPE = 0x11;
  public static final short INVALID_CBOR = 0x12;
  public static final short MISSING_PARAMETER = 0x14;
  public static final short LIMIT_EXCEEDED = 0x15;
  public static final short CREDENTIAL_EXCLUDED = 0x19;
  public static final short UNSUPPORTED_ALGORITHM = 0x26;
  public static final short OPERATION_DENIED = 0x27;
  public static final short KEY_STORE_FULL = 0x28;
  public static final short UNSUPPORTED_OPTION = 0x2B;
  public static final short INVALID_OPTION = 0x2C;
  public static final short NO_CREDENTIALS = 0x2E;
  public static final short NOT_ALLOWED = 0x30;
  public static final short PIN_INVALID = 0x31;
  public static final short PIN_BLOCKED = 0x32;
  public static final short PIN_AUTH_INVALID = 0x33;
  public static final short PIN_AUTH_BLOCKED = 0x34;
  public static final short PIN_NOT_SET = 0x35;
  public static final short PIN_REQUIRED = 0x36;
  public static final short PIN_POLICY_VIOLATION = 0x37;
  public static final short OTHER = 0x7F;

  public static final short MAX_MESSAGE_LENGTH = 1200;
}
