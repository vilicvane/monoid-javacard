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
  public static final byte JOIN_BUNDLE = 12;
  public static final byte RESET_IDENTITY = 13;
  public static final byte BORROW_RESULT = 14;
  public static final byte READ_RESULT = 15;
  public static final byte ENCRYPT_REENTRANT = 16;
  public static final byte GET_TOKEN = 17;
  public static final byte MUTATE_TOKEN_COPY = 18;
  public static final byte GET_TOKEN_ABORT_TRANSACTION = 19;
  public static final byte RESET_IDENTITY_WITHOUT_TRANSACTION = 20;
  public static final byte ENCRYPT_RESET_REENTRANT = 21;
  public static final byte PREPARE_RESET = 22;
  public static final byte PREPARE_RESET_IN_TRANSACTION = 23;
  public static final byte ENCRYPT_PREPARE_RESET_REENTRANT = 24;
  public static final byte IS_SECRET_PIN_SET = 25;
  public static final byte GET_SECRET_PIN_TRIES_REMAINING = 26;
  public static final byte CHECK_SECRET_PIN = 27;
  public static final byte UPDATE_SECRET_PIN = 28;
  public static final byte GET_SECRET_PIN_VALIDATION_RESULT = 29;
  public static final byte CLEAR_SECRET_AUTH = 30;
  public static final byte ENCRYPT_CHECK_SECRET_PIN_REENTRANT = 31;
  public static final byte ENCRYPT_UPDATE_SECRET_PIN_REENTRANT = 32;
  public static final byte ENCRYPT_CLEAR_SECRET_AUTH_REENTRANT = 33;
  public static final byte DECRYPT_CHECK_SECRET_PIN_REENTRANT = 34;
  public static final byte DECRYPT_UPDATE_SECRET_PIN_REENTRANT = 35;
  public static final byte DECRYPT_CLEAR_SECRET_AUTH_REENTRANT = 36;
  public static final byte APPROVE_BUNDLE_EXTENSION = 37;
  public static final byte EXTEND_BUNDLE = 38;
  public static final byte GET_AUTHORITY = 39;
  public static final byte MUTATE_AUTHORITY_COPY = 40;

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
      case GET_AUTHORITY:
        byte[] authority = identity.getAuthority();
        send(apdu, authority == null ? new byte[0] : authority);
        return;
      case MUTATE_AUTHORITY_COPY:
        byte[] authorityCopy = identity.getAuthority();
        authorityCopy[0] ^= (byte) 0xFF;
        send(apdu, authorityCopy);
        return;
      case IS_SECRET_PIN_SET:
        send(apdu, new byte[] { identity.isSecretPINSet() ? (byte) 1 : 0 });
        return;
      case GET_SECRET_PIN_TRIES_REMAINING:
        sendShort(apdu, identity.getSecretPINTriesRemaining());
        return;
      case CHECK_SECRET_PIN:
        send(apdu, new byte[] { identity.checkSecretPIN(buffer) ? (byte) 1 : 0 });
        return;
      case UPDATE_SECRET_PIN:
        identity.updateSecretPIN(buffer);
        return;
      case GET_SECRET_PIN_VALIDATION_RESULT:
        sendShort(apdu, identity.getSecretPINValidationResult());
        return;
      case CLEAR_SECRET_AUTH:
        identity.clearSecretAuth();
        return;
      case GET_TOKEN:
        send(apdu, identity.getToken());
        return;
      case MUTATE_TOKEN_COPY:
        byte[] token = identity.getToken();
        token[0] ^= (byte) 0xFF;
        send(apdu, token);
        return;
      case GET_TOKEN_ABORT_TRANSACTION:
        byte[] transactionToken = (byte[]) JCSystem.makeGlobalArray(
          JCSystem.ARRAY_TYPE_BYTE,
          (short) 32
        );
        JCSystem.beginTransaction();

        try {
          Util.arrayCopyNonAtomic(
            identity.getToken(),
            (short) 0,
            transactionToken,
            (short) 0,
            (short) transactionToken.length
          );
        } finally {
          JCSystem.abortTransaction();
        }

        send(apdu, transactionToken);
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
      case ENCRYPT_RESET_REENTRANT:
      case ENCRYPT_PREPARE_RESET_REENTRANT:
      case ENCRYPT_CHECK_SECRET_PIN_REENTRANT:
      case ENCRYPT_UPDATE_SECRET_PIN_REENTRANT:
      case ENCRYPT_CLEAR_SECRET_AUTH_REENTRANT:
      case DECRYPT_CHECK_SECRET_PIN_REENTRANT:
      case DECRYPT_UPDATE_SECRET_PIN_REENTRANT:
      case DECRYPT_CLEAR_SECRET_AUTH_REENTRANT:
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
        boolean decrypt =
          instruction == DECRYPT_DATA ||
          instruction == DECRYPT_CHECK_SECRET_PIN_REENTRANT ||
          instruction == DECRYPT_UPDATE_SECRET_PIN_REENTRANT ||
          instruction == DECRYPT_CLEAR_SECRET_AUTH_REENTRANT;
        Data source = instruction == ENCRYPT_REENTRANT ||
          instruction == ENCRYPT_RESET_REENTRANT ||
          instruction == ENCRYPT_PREPARE_RESET_REENTRANT ||
          instruction == ENCRYPT_CHECK_SECRET_PIN_REENTRANT ||
          instruction == ENCRYPT_UPDATE_SECRET_PIN_REENTRANT ||
          instruction == ENCRYPT_CLEAR_SECRET_AUTH_REENTRANT ||
          instruction == DECRYPT_CHECK_SECRET_PIN_REENTRANT ||
          instruction == DECRYPT_UPDATE_SECRET_PIN_REENTRANT ||
          instruction == DECRYPT_CLEAR_SECRET_AUTH_REENTRANT
          ? new Data(data) {
            @Override
            public void read(short dataOffset, byte[] buffer, short offset, short length) {
              if (instruction == ENCRYPT_RESET_REENTRANT) {
                JCSystem.beginTransaction();
                try {
                  identity.reset();
                } finally {
                  if (JCSystem.getTransactionDepth() != 0) {
                    JCSystem.abortTransaction();
                  }
                }
              } else if (instruction == ENCRYPT_PREPARE_RESET_REENTRANT) {
                identity.prepareReset();
              } else if (
                instruction == ENCRYPT_CHECK_SECRET_PIN_REENTRANT ||
                instruction == DECRYPT_CHECK_SECRET_PIN_REENTRANT
              ) {
                identity.checkSecretPIN(
                  (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) 6)
                );
              } else if (
                instruction == ENCRYPT_UPDATE_SECRET_PIN_REENTRANT ||
                instruction == DECRYPT_UPDATE_SECRET_PIN_REENTRANT
              ) {
                identity.updateSecretPIN(
                  (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) 6)
                );
              } else if (
                instruction == ENCRYPT_CLEAR_SECRET_AUTH_REENTRANT ||
                instruction == DECRYPT_CLEAR_SECRET_AUTH_REENTRANT
              ) {
                identity.clearSecretAuth();
              } else {
                identity.createBundle(identity.getPublicKey());
              }
              super.read(dataOffset, buffer, offset, length);
            }
          }
          : new Data(data);
        result = decrypt
          ? identity.decryptData(index, null, context, publicKey, source)
          : identity.encryptData(index, null, context, (short) 0x5AFE, publicKey, source);
        send(apdu, readResult(decrypt ? (short) 2 : (short) 0));
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
      case APPROVE_BUNDLE_EXTENSION:
        result = identity.approveBundleExtension(duplicate(buffer, (short) 0, length));
        send(apdu, readResult((short) 0));
        return;
      case EXTEND_BUNDLE:
        result = identity.extendBundle(duplicate(buffer, (short) 0, length));
        send(apdu, readResult((short) 0));
        return;
      case JOIN_BUNDLE:
        send(
          apdu,
          identity.joinBundle(
            duplicate(buffer, (short) 0, (short) 65),
            duplicate(buffer, (short) 65, (short) (length - 65))
          )
        );
        return;
      case PREPARE_RESET:
        send(apdu, identity.prepareReset());
        return;
      case PREPARE_RESET_IN_TRANSACTION:
        JCSystem.beginTransaction();
        try {
          identity.prepareReset();
        } finally {
          JCSystem.abortTransaction();
        }
        return;
      case RESET_IDENTITY:
        byte[] depth = new byte[1];
        JCSystem.beginTransaction();
        try {
          identity.reset();
          depth[0] = JCSystem.getTransactionDepth();
          JCSystem.commitTransaction();
        } finally {
          if (JCSystem.getTransactionDepth() != 0) {
            JCSystem.abortTransaction();
          }
        }
        send(apdu, depth);
        return;
      case RESET_IDENTITY_WITHOUT_TRANSACTION:
        identity.reset();
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

  private void sendShort(APDU apdu, short value) {
    byte[] data = new byte[2];
    Util.setShort(data, (short) 0, value);
    send(apdu, data);
  }
}
