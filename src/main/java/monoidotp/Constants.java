package monoidotp;

public final class Constants {

  public static final short ACCOUNT_TYPE = (short) 0xF201;
  public static final short BATCH_SIZE = 3;
  public static final short MAX_ACCOUNTS = 16;
  public static final short INDEX_LENGTH = 10;
  public static final short CHALLENGE_LENGTH = 32;

  // prettier-ignore
  public static final byte[] MONOID_AID =
    // @inplate-line { {{java-readable MONOID_AID}} };
    { (byte) 0xf0, 'm', 'o', 'n', 'o', 'i', 'd', 0x02, 0x01 };

  // prettier-ignore
  public static final byte[] MONOID_IDENTITY_AID =
    // @inplate-line { {{java-readable MONOID_IDENTITY_AID}} };
    { (byte) 0xf0, 'm', 'o', 'n', 'o', 'i', 'd', 0x00, 0x01 };

  // prettier-ignore
  public static final byte[] VERSION =
    // @inplate-line { {{java-readable MONOID_VERSION}} };
    { 0x00, 0x00 };
}
