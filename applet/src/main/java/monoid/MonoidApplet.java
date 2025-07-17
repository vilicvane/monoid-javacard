package monoid;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;

import monoidstore.MonoidStore;

public class MonoidApplet extends Applet implements Monoid, AppletEvent, ExtendedLength {
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    SECP256k1.init();
    HmacSHA512.init();

    new MonoidApplet().register();
  }

  public void uninstall() {
    SECP256k1.dispose();
    HmacSHA512.dispose();
  }

  private static final byte[] PIN = { (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0' };

  private short version = 0;

  private MonoidStore store;
  private Keystore keystore;

  private CBORReader reader = new CBORReader();
  private CBORWriter writer = new CBORWriter();

  public void process(APDU apdu) {
    if (version == 0) {
      byte[] buffer = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);

      short length = JCSystem.getAID().getBytes(buffer, (short) 0);

      version = Util.getShort(buffer, (short) (length - 2));
    }

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
      case 0x20:
        hello(apdu);
        break;
      case 0x01:
        short publicKeyLength = keystore.genKey(Keystore.TYPE_SECP256K1, buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, publicKeyLength);
        break;
      case 0x02:
        short signatureLength = keystore.sign(
            buffer,
            ISO7816.OFFSET_CDATA,
            (short) (Keystore.STORE_INDEX_LENGTH + ISO7816.OFFSET_CDATA), (byte) 32,
            buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, signatureLength);
        break;
      case 0x03:
        short offset = ISO7816.OFFSET_CDATA;

        byte[] key = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);

        Util.arrayCopyNonAtomic(buffer, offset, key, (short) 0, (short) 32);

        short digestLength = HmacSHA512.digest(
            // key
            key, (short) 0, (short) 32,
            // data
            buffer, (short) (offset + 32), (short) 37,
            buffer, (short) 0);

        apdu.setOutgoingAndSend((short) 0, digestLength);
        break;
      case 0x04:
        byte[] privateKeyAndChainCode = JCSystem.makeTransientByteArray((short) (SECP256k1.KEY_BYTES * 2),
            JCSystem.CLEAR_ON_DESELECT);

        short pathOffset = (short) (ISO7816.OFFSET_CDATA
            + Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, privateKeyAndChainCode, (short) 0,
                (short) (SECP256k1.KEY_BYTES * 2)));

        BIP32.deriveChildKey(privateKeyAndChainCode, buffer, pathOffset);

        Util.arrayCopyNonAtomic(privateKeyAndChainCode, (short) 0, buffer, (short) 0,
            (short) privateKeyAndChainCode.length);

        apdu.setOutgoingAndSend((short) 0, (short) privateKeyAndChainCode.length);
        break;
      case 0x05:
        short length = store.get(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC]);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, length);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    // ISOException.throwIt(ISO7816.SW_NO_ERROR);
  }

  private void hello(APDU apdu) {
    byte[] buffer = apdu.getBuffer();

    writer.bind(buffer, (short) 0);

    writer.map((short) 2);

    writer.text(Text.versions);
    writer.map((short) 2);

    // versions.monoid
    writer.text(Text.monoid);
    writer.integer((short) version);

    // versions.javacard
    writer.text(Text.javacard);
    writer.array((short) 2);
    writer.integer((short) (JCSystem.getVersion() >> 8));
    writer.integer((short) (JCSystem.getVersion() & 0xFF));

    writer.text(Text.pins);
    writer.map((short) 2);

    // pins.store
    writer.text(Text.store);
    writer.bool(false);

    // pins.access
    writer.text(Text.access);
    writer.bool(false);

    apdu.setOutgoingAndSend((short) 0, writer.getLength());
  }

  @Override
  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    return this;
  }
}
