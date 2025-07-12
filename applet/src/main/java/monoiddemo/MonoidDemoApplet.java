package monoiddemo;

import javacard.framework.*;
import monoid.Monoid;

public class MonoidDemoApplet extends Applet {
  private Monoid monoid;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new MonoidDemoApplet();
  }

  public MonoidDemoApplet() {
    register();
  }

  public void process(APDU apdu) {
    byte[] buffer = apdu.getBuffer();

    buffer[0] = (byte) requireMonoid().getId();

    apdu.setOutgoingAndSend((short) 0, (short) 1);
  }

  private Monoid requireMonoid() {
    if (monoid != null) {
      return monoid;
    }

    monoid = (Monoid) JCSystem.getAppletShareableInterfaceObject(
        new AID(new byte[] { 0x6d, 0x6f, 0x6e, 0x6f, 0x69, 0x64, 0x00, 0x00 }, (short) 0, (byte) 8),
        (byte) 0x00);

    if (monoid == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    return monoid;
  }
}
