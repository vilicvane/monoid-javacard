package monoidsafeidentity;

public final class Constants {

  public static final short SAFE_FALSE = (short) 0xA501;
  public static final short SAFE_TRUE = (short) 0x5AFE;

  // prettier-ignore
  public static final byte[] MONOID_AID_WITHOUT_VERSION =
    // @inplate-line { {{java-readable MONOID_AID_WITHOUT_VERSION}} };
    { (byte) 0xf0, 'm', 'o', 'n', 'o', 'i', 'd', 0x02, 0x01 };
}
