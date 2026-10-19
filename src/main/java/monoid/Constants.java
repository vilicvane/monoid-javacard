package monoid;

public final class Constants {

  public static final short SAFE_FALSE = (short) 0xA501;
  public static final short SAFE_TRUE = (short) 0x5AFE;

  // prettier-ignore
  public static final byte[] MONOID_IDENTITY_AID =
    // @inplate-line { {{java-readable MONOID_IDENTITY_AID}} };
    { (byte) 0xf0, 'm', 'o', 'n', 'o', 'i', 'd', 0x00, 0x01, 0x00, 0x00 };
}
