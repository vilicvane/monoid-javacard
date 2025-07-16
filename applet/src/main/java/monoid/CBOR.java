package monoid;

public final class CBOR {
  public static final byte TYPE_UNSIGNED_INT = 0 << 5;
  public static final byte TYPE_NEGATIVE_INT = 1 << 5;
  public static final byte TYPE_BYTES = 2 << 5;
  public static final byte TYPE_TEXT = 3 << 5;
  public static final byte TYPE_ARRAY = (byte) (4 << 5);
  public static final byte TYPE_MAP = (byte) (5 << 5);
  public static final byte TYPE_TAG = (byte) (6 << 5);
  public static final byte TYPE_SIMPLE_FLOAT = (byte) (7 << 5);

  public static final byte TYPE_MASK = (byte) 0b11100000;
  public static final byte METADATA_MASK = 0b00011111;

  public static final byte FALSE = (byte) 0xF4;
  public static final byte TRUE = (byte) 0xF5;
}
