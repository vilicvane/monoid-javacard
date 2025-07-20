package monoiddemo;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
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
    @SuppressWarnings("unused")
    Monoid monoid = requireMonoid();
  }

  private Monoid requireMonoid() {
    if (monoid != null) {
      return monoid;
    }

    monoid = (Monoid) JCSystem.getAppletShareableInterfaceObject(
      JCSystem.lookupAID(
        Constants.MONOID_AID,
        (short) 0,
        (byte) Constants.MONOID_AID.length
      ),
      (byte) 0x00
    );

    if (monoid == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    return monoid;
  }
}
