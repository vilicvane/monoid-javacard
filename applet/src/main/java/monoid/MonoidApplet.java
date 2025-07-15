package monoid;

import javacard.framework.*;
import javacard.security.*;

import monoidstore.MonoidStore;

public class MonoidApplet extends Applet implements Monoid, AppletEvent {
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    SECP256k1.sharedPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
        JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false);

    SECP256k1.sharedKeyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);

    try {
      HmacSHA512.sharedSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
      HmacSHA512.sharedKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
          KeyBuilder.LENGTH_AES_256, false);
    } catch (Exception e) {
      HmacSHA512.sharedSignature = null;
      HmacSHA512.sharedKey = null;
      HmacSHA512.sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
    }

    new MonoidApplet().register();
  }

  public void uninstall() {
    SECP256k1.sharedPrivateKey = null;
    SECP256k1.sharedKeyAgreement = null;
    HmacSHA512.sharedSignature = null;
    HmacSHA512.sharedKey = null;
    HmacSHA512.sha512 = null;
  }

  private static final byte[] PIN = { (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0' };

  private MonoidStore store;

  private Keystore keystore;

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
        short publicKeyLength = keystore.genKey(Keystore.TYPE_SECP256K1, buffer, (short) 0);
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
}
