package monoid;

import javacard.framework.*;
import javacard.security.*;
import monoidkeystore.MonoidKeystore;

public class MonoidApplet extends Applet implements Monoid {
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new MonoidApplet();
  }

  private static final byte[] PIN = { (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0' };

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
    if (keystore == null) {
      keystore = new KeystoreWrapper(
          (MonoidKeystore) JCSystem.getAppletShareableInterfaceObject(
              new AID(Constants.MONOID_KEYSTORE_AID, (short) 0, (byte) Constants.MONOID_KEYSTORE_AID.length),
              (byte) 0));
    }

    if (selectingApplet()) {
      return;
    }

    byte[] buffer = apdu.getBuffer();

    try {
      Util.arrayCopyNonAtomic(PIN, (short) 0, buffer, (short) 0, (short) PIN.length);

      keystore.verifyPIN(buffer, (short) 0, (byte) PIN.length);
    } catch (SecurityException e) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    KeyPair keyPair = keystore.ensureOneECKeyPair(Monoid.KEY_TYPE_ECDSA_SECP256K1);

    // ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

    short publicKeyLength = publicKey.getW(buffer, (short) 0);

    apdu.setOutgoingAndSend((short) 0, publicKeyLength);

    // ISOException.throwIt(ISO7816.SW_NO_ERROR);

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
