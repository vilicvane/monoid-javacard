package monoid;

public final class Constants {
  public static final byte[] MONOID_STORE_AID = new byte[] {
      (byte) 0xF1,
      (byte) 'm', (byte) 'o', (byte) 'n', (byte) 'o', (byte) 'i', (byte) 'd',
      (byte) 0x00, // package monoidstore
      (byte) 0x01, // applet MonoidStoreApplet
      (byte) 0x00, (byte) 0x01 // version 1
  };
}
