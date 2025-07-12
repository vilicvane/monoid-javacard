package monoid;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;
import monoid.lib.KeystoreWrapper;
import monoidkeystore.MonoidKeystore;
import monoidkeystore.MonoidKeystoreApplet;

public class MonoidApplet extends Applet implements Monoid {
  private static AID aid;

  public static AID getAID() {
    return aid;
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new MonoidApplet();
  }

  // private MonoidKeyPair[] keyPairs;

  // private Signature signature;

  private KeystoreWrapper keystore;

  public MonoidApplet() {
    // try {
    // signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    // } catch (CryptoException exception) {
    // ISOException.throwIt(exception.getReason());
    // }

    register();
  }

  public void process(APDU apdu) {
    if (aid == null) {
      aid = JCSystem.getAID();
    }

    if (keystore == null) {
      keystore = new KeystoreWrapper(
          (MonoidKeystore) JCSystem.getAppletShareableInterfaceObject(MonoidKeystoreApplet.getAID(), (byte) 0));
    }

    if (selectingApplet()) {
      return;
    }

    keystore.verifyPIN(new byte[] { (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0' }, (short) 0,
        (byte) 6);

    KeyPair keyPair = keystore.ensureOneECKeyPair(Monoid.KEY_TYPE_ECDSA_SECP256K1);

    System.out.println(keyPair);

    ISOException.throwIt(ISO7816.SW_NO_ERROR);

    // keyPairs = new MonoidKeyPair[1];
    // keyPairs[0] = new MonoidKeyPair(MonoidKeyPair.ALGORITHM_SECP256K1);
    // // ISOException.throwIt(ISO7816.SW_FILE_INVALID);

    // byte[] buffer = apdu.getBuffer();

    // short length = keyPairs[0].sign(signature, buffer, (short) 0, (short) 32,
    // buffer, (short) 0);

    // apdu.setOutgoingAndSend((short) 0, length);
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
