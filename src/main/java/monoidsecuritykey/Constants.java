package monoidsecuritykey;

public final class Constants {

  public static final short SAFE_FALSE = (short) 0xA501;
  public static final short SAFE_TRUE = (short) 0x5AFE;
  public static final short CREDENTIAL_TYPE = (short) 0xF101;

  // prettier-ignore
  public static final byte[] MONOID_AID =
    // @inplate-line { {{java-readable MONOID_AID}} };
    { (byte) 0xf0, 'm', 'o', 'n', 'o', 'i', 'd', 0x02, 0x01 };

  // @formatter:off
  public static final byte[] FIDO_VERSION = {'F','I','D','O','_','2','_','0'};
  public static final byte[] KEY_TYPE = {'t','y','p','e'};
  public static final byte[] KEY_ID = {'i','d'};
  public static final byte[] KEY_NAME = {'n','a','m','e'};
  public static final byte[] KEY_DISPLAY_NAME = {'d','i','s','p','l','a','y','N','a','m','e'};
  public static final byte[] KEY_ALG = {'a','l','g'};
  public static final byte[] KEY_RK = {'r','k'};
  public static final byte[] KEY_UP = {'u','p'};
  public static final byte[] KEY_UV = {'u','v'};
  public static final byte[] KEY_CLIENT_PIN = {'c','l','i','e','n','t','P','i','n'};
  public static final byte[] KEY_PUBLIC_KEY = {'p','u','b','l','i','c','-','k','e','y'};
  public static final byte[] KEY_SIG = {'s','i','g'};
  public static final byte[] FORMAT_PACKED = {'p','a','c','k','e','d'};
  public static final byte[] DERIVATION_CONTEXT = {'m','o','n','o','i','d',' ','f','i','d','o','2',':',' '};
  // @formatter:on
}
