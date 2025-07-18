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
  public static final byte METADATA_BYTES_LENGTH_MASK = 0b111;

  public static final short MAX_SIMPLE_UNSIGNED_INT = 0b00010111;
  public static final short VARIABLE_LENGTH_UNSIGNED_INT_MARK = 0b11000;
  public static final byte VARIABLE_LENGTH_INDEFINITE_MARK = 0b11111;

  public static final byte FALSE = (byte) 0b11110100;
  public static final byte TRUE = (byte) 0b11110101;
  public static final byte BREAK = (byte) 0b11111111;
}
