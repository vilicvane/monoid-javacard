package tests;

import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import monoidsafe.SafeShareable;
import monoidsafeidentity.SafeIdentityShareable;

/** Exercises Identity through applet calls, including forwarding its interface. */
public class IdentityCallerApplet extends Applet implements IdentityCallerShareable {

  public static final byte GET_SHAREABLE = 1;
  public static final byte GET_PUBLIC_KEY = 2;
  public static final byte ENCRYPT_KEY = 3;
  public static final byte DECRYPT_KEY = 4;
  public static final byte BORROW_IDENTITY = 5;
  public static final byte GET_SAFE_ID = 6;
  public static final byte GET_IDENTITY_ID = 7;
  public static final byte MUTATE_ID_COPY = 8;

  private static final AID SAFE_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_AID}}"
    "f06d6f6e6f696401010000"
  );

  private SafeIdentityShareable identity;

  public static void install(byte[] buffer, short offset, byte length) {
    new IdentityCallerApplet().register();
  }

  @Override
  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    byte[] buffer = apdu.getBuffer();
    byte instruction = buffer[ISO7816.OFFSET_INS];
    short length = apdu.setIncomingAndReceive();

    switch (instruction) {
      case GET_SHAREABLE:
        AID identityAID = JCSystem.lookupAID(buffer, ISO7816.OFFSET_CDATA, (byte) length);
        SafeIdentityShareable previous = identity;
        identity = (SafeIdentityShareable) JCSystem.getAppletShareableInterfaceObject(
          identityAID,
          (byte) 0
        );

        if (identity == null) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        buffer[0] = identity == previous ? (byte) 1 : 0;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
        return;
      case GET_PUBLIC_KEY:
        send(apdu, identity.getPublicKey());
        return;
      case GET_IDENTITY_ID:
        send(apdu, identity.getId());
        return;
      case MUTATE_ID_COPY:
        byte[] id = identity.getId();
        id[0] ^= (byte) 0xFF;
        send(apdu, id);
        return;
      case ENCRYPT_KEY:
      case DECRYPT_KEY:
        byte[] publicKey = duplicate(buffer, ISO7816.OFFSET_CDATA, (short) 65);
        short contextLength = (short) (buffer[(short) (ISO7816.OFFSET_CDATA + 65)] & 0xFF);
        short contextOffset = (short) (ISO7816.OFFSET_CDATA + 66);
        byte[] context = duplicate(buffer, contextOffset, contextLength);
        byte[] data = duplicate(
          buffer,
          (short) (contextOffset + contextLength),
          (short) (length - 66 - contextLength)
        );

        send(
          apdu,
          instruction == ENCRYPT_KEY
            ? identity.encryptCommunicationKey(publicKey, context, data)
            : identity.decryptCommunicationKey(publicKey, context, data)
        );
        return;
      case BORROW_IDENTITY:
        AID callerAID = JCSystem.lookupAID(buffer, ISO7816.OFFSET_CDATA, (byte) length);
        IdentityCallerShareable caller =
          (IdentityCallerShareable) JCSystem.getAppletShareableInterfaceObject(callerAID, (byte) 0);
        identity = caller.getIdentity();
        return;
      case GET_SAFE_ID:
        SafeShareable safe = (SafeShareable) JCSystem.getAppletShareableInterfaceObject(
          SAFE_AID,
          (byte) 0
        );
        send(apdu, safe.getId());
        return;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }

  @Override
  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    return this;
  }

  @Override
  public SafeIdentityShareable getIdentity() {
    return identity;
  }

  private byte[] duplicate(byte[] buffer, short offset, short length) {
    byte[] duplicate = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, length);
    Util.arrayCopyNonAtomic(buffer, offset, duplicate, (short) 0, length);
    return duplicate;
  }

  private void send(APDU apdu, byte[] data) {
    Util.arrayCopyNonAtomic(data, (short) 0, apdu.getBuffer(), (short) 0, (short) data.length);
    apdu.setOutgoingAndSend((short) 0, (short) data.length);
  }
}
