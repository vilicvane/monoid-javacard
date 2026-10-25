package monoidsecuritykey;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import monoidlib.CBORApduReader;
import monoidlib.CBORApduWriter;
import monoidlib.CBORReader;

/** CTAP NFC framing over the shared APDU reader and writer. */
final class ApduTransport {

  private static final short CHAINING = 0;
  private static final short DISABLED = 1;

  private final short[] state = JCSystem.makeTransientShortArray(
    (short) 2,
    JCSystem.CLEAR_ON_DESELECT
  );
  private byte[] response;
  private CBORApduReader reader;
  private CBORApduWriter writer;

  void clear() {
    for (short index = 0; index < state.length; index++) {
      state[index] = 0;
    }
    if (reader != null) {
      reader.clear();
    }
    if (writer != null) {
      writer.reset((short) 1);
    }
  }

  void process(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte cla = buffer[ISO7816.OFFSET_CLA];
    byte instruction = buffer[ISO7816.OFFSET_INS];
    if (cla == 0 && instruction == ISO7816.INS_SELECT) {
      short disabled = state[DISABLED];
      clear();
      Command.clear();
      state[DISABLED] = disabled;
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    if (state[DISABLED] != 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if ((cla == 0 || cla == (byte) 0x80) && instruction == (byte) 0xC0) {
      if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
        reject(ISO7816.SW_INCORRECT_P1P2);
      }
      send(apdu);
      return;
    }
    if (
      cla == (byte) 0x80 &&
      instruction == 0x12 &&
      buffer[ISO7816.OFFSET_P1] == 1 &&
      buffer[ISO7816.OFFSET_P2] == 0
    ) {
      clear();
      Command.clear();
      state[DISABLED] = 1;
      return;
    }
    if (cla != (byte) 0x80 && cla != (byte) 0x90) {
      reject(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    if (instruction != 0x10) {
      reject(ISO7816.SW_INS_NOT_SUPPORTED);
    }
    // P1 bit 7 advertises support for NFCCTAP_GETRESPONSE; synchronous replies need no 9100.
    if ((buffer[ISO7816.OFFSET_P1] & 0x7F) != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
      reject(ISO7816.SW_INCORRECT_P1P2);
    }

    if (writer != null) {
      writer.reset((short) 1);
    }
    if (reader != null && state[CHAINING] == 0) {
      reader.clear();
    }
    short received = apdu.setIncomingAndReceive();
    short incoming = apdu.getIncomingLength();
    short length = reader != null ? reader.getReceivedLength() : (short) 0;
    if (incoming == 0 || incoming > (short) (CTAP.MAX_MESSAGE_LENGTH - length) || received <= 0) {
      reject(ISO7816.SW_WRONG_LENGTH);
    }
    if (reader == null) {
      reader = new CBORApduReader(CTAP.MAX_MESSAGE_LENGTH, CBORReader.PROFILE_CTAP);
    }
    if (!reader.receive(apdu, received, apdu.getOffsetCdata(), false)) {
      reject(ISO7816.SW_WRONG_LENGTH);
    }
    state[CHAINING] = cla == (byte) 0x90 ? (short) 1 : (short) 0;
    if (state[CHAINING] != 0) {
      return;
    }

    if (response == null) {
      response = new byte[1024];
    }
    byte[] request = reader.getBuffer();
    short responseLength;
    try {
      if (writer == null) {
        writer = new CBORApduWriter(response, CTAP.LIMIT_EXCEEDED);
      }
      reader.reset((short) 1, (short) (reader.getReceivedLength() - 1));
      // Assertion inputs are private before encoding. PIN responses still borrow the APDU tail.
      writer.reset(
        (short) 1,
        request[0] == 0x02 || request[0] == 0x08 ? (short) buffer.length : (short) 0
      );
      Command.process(request[0], reader, writer);
      if (writer.isDirect()) {
        buffer[0] = 0;
      } else {
        response[0] = 0;
      }
      responseLength = (short) (writer.getLength() + 1);
    } catch (ISOException exception) {
      if (writer != null) {
        writer.reset((short) 1);
      }
      short status = exception.getReason();
      response[0] = status > 0 && status < 256
        ? (byte) status
        : status == ISO7816.SW_FILE_FULL
          ? (byte) CTAP.KEY_STORE_FULL
          : status == ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED ||
            status == ISO7816.SW_CONDITIONS_NOT_SATISFIED
            ? (byte) CTAP.OPERATION_DENIED
            : (byte) CTAP.OTHER;
      responseLength = 1;
      Command.clear();
    } catch (RuntimeException exception) {
      if (writer != null) {
        writer.reset((short) 1);
      }
      response[0] = (byte) CTAP.OTHER;
      responseLength = 1;
      Command.clear();
    } finally {
      reader.clear();
      JCSystem.requestObjectDeletion();
    }
    if (writer == null) {
      // Encoding storage could not be allocated; the CTAP error itself needs only one byte.
      buffer[0] = response[0];
      apdu.setOutgoingAndSend((short) 0, (short) 1);
    } else {
      writer.send(apdu, responseLength);
    }
  }

  private void send(APDU apdu) {
    if (writer == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    writer.send(apdu);
  }

  private void reject(short status) {
    clear();
    Command.clear();
    ISOException.throwIt(status);
  }
}
