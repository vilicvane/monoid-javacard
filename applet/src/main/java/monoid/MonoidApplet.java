package monoid;

import javacard.framework.*;
import monoidstore.MonoidStore;

public class MonoidApplet extends Applet implements Monoid {
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new MonoidApplet();
  }

  private static final byte[] PIN = { (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0' };

  private MonoidStore store;

  private Keystore keystore;

  public MonoidApplet() {
    register();
  }

  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    if (store == null) {
      store = (MonoidStore) JCSystem.getAppletShareableInterfaceObject(
          JCSystem.lookupAID(Constants.MONOID_STORE_AID, (short) 0, (byte) Constants.MONOID_STORE_AID.length),
          (byte) 0);

      if (store == null) {
        ISOException.throwIt(ISO7816.SW_FILE_INVALID);
      }
    }

    byte[] pin = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) PIN.length);

    Util.arrayCopyNonAtomic(PIN, (short) 0, pin, (short) 0, (short) PIN.length);

    store.verifyPIN(pin, (short) 0, (byte) PIN.length);

    if (keystore == null) {
      keystore = new Keystore(store);
    }

    // ISOException.throwIt(ISO7816.SW_NO_ERROR);

    byte[] buffer = apdu.getBuffer();

    switch (buffer[ISO7816.OFFSET_INS]) {
      case 0x01:
        short publicKeyLength = keystore.genKey(Constants.STORE_ITEM_TYPE_SECP256K1, buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, publicKeyLength);
        break;
      case 0x02:
        short signatureLength = keystore.sign(
            buffer,
            ISO7816.OFFSET_CDATA,
            (short) (ISO7816.OFFSET_CDATA + Keystore.STORE_INDEX_LENGTH), (byte) 32,
            buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, signatureLength);
        break;
      case (byte) 0x90:
        short length = store.get(buffer, ISO7816.OFFSET_CDATA, (byte) 1);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, length);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    // ISOException.throwIt(ISO7816.SW_NO_ERROR);
  }

  @Override
  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    return this;
  }

  @Override
  public short getId() {
    return 0x01;
  }
}
