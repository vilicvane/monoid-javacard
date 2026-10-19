package tests;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;
import monoididentity.CommunicationDataShareable;
import monoididentity.IdentityShareable;

/** Exercises Identity through applet calls, including forwarding its interface. */
public class IdentityCallerApplet
  extends Applet
  implements IdentityCallerShareable, ExtendedLength {

  public static final byte GET_SHAREABLE = 1;
  public static final byte GET_PUBLIC_KEY = 2;
  public static final byte ENCRYPT_DATA = 3;
  public static final byte DECRYPT_DATA = 4;
  public static final byte BORROW_IDENTITY = 5;
  public static final byte GET_IDENTITY_ID = 7;
  public static final byte MUTATE_ID_COPY = 8;
  public static final byte GET_BUNDLE = 9;
  public static final byte CREATE_BUNDLE = 10;
  public static final byte IMPORT_BUNDLE = 12;
  public static final byte RESET_BUNDLE = 13;
  public static final byte BORROW_RESULT = 14;
  public static final byte READ_RESULT = 15;
  public static final byte ENCRYPT_REENTRANT = 16;

  private IdentityShareable identity;
  private CommunicationDataShareable result;

  public static void install(byte[] buffer, short offset, byte length) {
    new IdentityCallerApplet().register();
  }

  @Override
  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    byte[] apduBuffer = apdu.getBuffer();
    byte instruction = apduBuffer[ISO7816.OFFSET_INS];
    short received = apdu.setIncomingAndReceive();
    short length = apdu.getIncomingLength();
    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, length);
    short copied = 0;

    while (received > 0) {
      Util.arrayCopyNonAtomic(apduBuffer, apdu.getOffsetCdata(), buffer, copied, received);
      copied += received;
      received = copied < length ? apdu.receiveBytes(apdu.getOffsetCdata()) : 0;
    }

    switch (instruction) {
      case GET_SHAREABLE:
        AID identityAID = JCSystem.lookupAID(buffer, (short) 0, (byte) length);
        IdentityShareable previous = identity;
        identity = (IdentityShareable) JCSystem.getAppletShareableInterfaceObject(
          identityAID,
          (byte) 0
        );

        if (identity == null) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        send(apdu, new byte[] { identity == previous ? (byte) 1 : 0 });
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
      case ENCRYPT_DATA:
      case DECRYPT_DATA:
      case ENCRYPT_REENTRANT:
        byte[] publicKey = duplicate(buffer, (short) 0, (short) 65);
        short contextLength = (short) (buffer[65] & 0xFF);
        short contextOffset = 66;
        byte[] context = duplicate(buffer, contextOffset, contextLength);
        byte[] data = duplicate(
          buffer,
          (short) (contextOffset + contextLength),
          (short) (length - 66 - contextLength)
        );

        byte[] index = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) 10);
        Data source = instruction == ENCRYPT_REENTRANT
          ? new Data(data) {
            @Override
            public void read(short dataOffset, byte[] buffer, short offset, short length) {
              identity.resetBundle();
              super.read(dataOffset, buffer, offset, length);
            }
          }
          : new Data(data);
        result = instruction != DECRYPT_DATA
          ? identity.encryptData(index, null, context, (short) 0x5AFE, publicKey, source)
          : identity.decryptData(index, null, context, publicKey, new Data(data));
        send(apdu, readResult(instruction != DECRYPT_DATA ? (short) 0 : (short) 2));
        return;
      case BORROW_IDENTITY:
      case BORROW_RESULT:
        AID callerAID = JCSystem.lookupAID(buffer, (short) 0, (byte) length);
        IdentityCallerShareable caller =
          (IdentityCallerShareable) JCSystem.getAppletShareableInterfaceObject(callerAID, (byte) 0);
        if (instruction == BORROW_IDENTITY) {
          identity = caller.getIdentity();
        } else {
          result = caller.getResult();
        }
        return;
      case READ_RESULT:
        send(apdu, readResult((short) 0));
        return;
      case GET_BUNDLE:
        byte[] bundle = identity.getBundle();
        send(apdu, bundle == null ? new byte[0] : bundle);
        return;
      case CREATE_BUNDLE:
        result = identity.createBundle(duplicate(buffer, (short) 0, length));
        send(apdu, readResult((short) 0));
        return;
      case IMPORT_BUNDLE:
        send(
          apdu,
          identity.importBundle(
            duplicate(buffer, (short) 0, (short) 65),
            duplicate(buffer, (short) 65, (short) (length - 65))
          )
        );
        return;
      case RESET_BUNDLE:
        identity.resetBundle();
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
  public IdentityShareable getIdentity() {
    return identity;
  }

  @Override
  public CommunicationDataShareable getResult() {
    return result;
  }

  private byte[] readResult(short offset) {
    short length = (short) (result.getLength() - offset);
    byte[] data = new byte[length];
    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) 64);

    for (short copied = 0; copied < length; ) {
      short chunkLength = (short) Math.min(length - copied, buffer.length);
      result.read((short) (offset + copied), buffer, (short) 0, chunkLength);
      Util.arrayCopyNonAtomic(buffer, (short) 0, data, copied, chunkLength);
      copied += chunkLength;
    }

    return data;
  }

  public static class Data implements CommunicationDataShareable {

    private final byte[] data;

    public Data(byte[] data) {
      this.data = data;
    }

    @Override
    public short getLength() {
      return (short) data.length;
    }

    @Override
    public void read(short dataOffset, byte[] buffer, short offset, short length) {
      Util.arrayCopyNonAtomic(data, dataOffset, buffer, offset, length);
    }
  }

  private byte[] duplicate(byte[] buffer, short offset, short length) {
    byte[] duplicate = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, length);
    Util.arrayCopyNonAtomic(buffer, offset, duplicate, (short) 0, length);
    return duplicate;
  }

  private void send(APDU apdu, byte[] data) {
    apdu.setOutgoing();
    apdu.setOutgoingLength((short) data.length);
    apdu.sendBytesLong(data, (short) 0, (short) data.length);
  }
}
