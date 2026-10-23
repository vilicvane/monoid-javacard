package monoid;

import monoidlib.LibSecurity;

public final class Constants {

  // @inplate-line public static final short MONOID_VERSION = (short) 0x{{hex MONOID_VERSION}};
  public static final short MONOID_VERSION = (short) 0x0000;

  public static final short SAFE_FALSE = LibSecurity.SAFE_FALSE;
  public static final short SAFE_TRUE = LibSecurity.SAFE_TRUE;

  // prettier-ignore
  public static final byte[] MONOID_IDENTITY_AID =
    // @inplate-line { {{java-readable MONOID_IDENTITY_AID}} };
    { (byte) 0xf0, 'm', 'o', 'n', 'o', 'i', 'd', 0x00, 0x01 };
}
