package monoid;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import monoidlib.CBORApduReader;
import monoidlib.CBORApduWriter;

/** Monoid command framing over the shared APDU reader and writer. */
final class ApduTransport {

  private static final byte CLA_SINGLE = 0x00;
  private static final byte CLA_FIRST = (byte) 0x90;
  private static final byte CLA_MORE = (byte) 0xB0;
  private static final byte CLA_LAST = (byte) 0xA0;

  private final byte[] header = JCSystem.makeTransientByteArray(
    (short) 3,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final short[] state = JCSystem.makeTransientShortArray(
    (short) 1,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final CBORApduReader reader;
  private final CBORApduWriter writer;

  ApduTransport(CBORApduReader reader, CBORApduWriter writer) {
    this.reader = reader;
    this.writer = writer;
  }

  void clear() {
    clearRequest();
    writer.reset();
    JCSystem.requestObjectDeletion();
  }

  void clearRequest() {
    state[0] = 0;
    reader.clear();
  }

  boolean isReceiving() {
    return state[0] != 0;
  }

  void process(APDU apdu) {
    byte[] incoming = apdu.getBuffer();
    byte cla = incoming[ISO7816.OFFSET_CLA];
    byte ins = incoming[ISO7816.OFFSET_INS];

    if (ins == (byte) 0xC0) {
      if (cla != CLA_SINGLE) {
        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
      }

      if (incoming[ISO7816.OFFSET_P1] != 0 || incoming[ISO7816.OFFSET_P2] != 0) {
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      }

      if (isReceiving()) {
        ISOException.throwIt(ISO7816.SW_LAST_COMMAND_EXPECTED);
      }

      if (!writer.hasPending()) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }

      try {
        writer.send();
      } catch (ISOException e) {
        short status = e.getReason();

        if (
          status != ISO7816.SW_NO_ERROR &&
          (short) (status & (short) 0xFF00) != ISO7816.SW_BYTES_REMAINING_00
        ) {
          clear();
        }

        throw e;
      } catch (Exception e) {
        // A response prefix has already been sent. Appending a CBOR error would
        // leave a malformed success response, so terminate the transport instead.
        clear();
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
      } finally {
        JCSystem.requestObjectDeletion();
      }

      return;
    }

    writer.reset();
    boolean pending = false;

    try {
      if (cla != CLA_SINGLE && cla != CLA_FIRST && cla != CLA_MORE && cla != CLA_LAST) {
        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
      }

      Command command = Command.get(ins);

      if (command == null) {
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }

      pending = !receive(apdu);

      if (pending) {
        return;
      }

      command.executeCommand();
    } finally {
      if (!pending) {
        clearRequest();
        JCSystem.requestObjectDeletion();
      }
    }
  }

  boolean receive(APDU apdu) {
    // Typed cleanup avoids the CAP converter's long catch-all reference gaps.
    try {
      return receiveFrame(apdu);
    } catch (RuntimeException exception) {
      clearRequest();
      throw exception;
    }
  }

  private boolean receiveFrame(APDU apdu) {
    byte[] incoming = apdu.getBuffer();
    byte cla = incoming[ISO7816.OFFSET_CLA];

    if (cla == CLA_SINGLE || cla == CLA_FIRST) {
      boolean replaced = reader.hasChunks();
      clearRequest();

      if (replaced) {
        JCSystem.requestObjectDeletion();
      }

      Util.arrayCopyNonAtomic(incoming, ISO7816.OFFSET_INS, header, (short) 0, (short) 3);

      if (cla == CLA_FIRST) {
        state[0] = 1;
      }
    } else if (cla == CLA_MORE || cla == CLA_LAST) {
      if (
        !isReceiving() ||
        Util.arrayCompare(incoming, ISO7816.OFFSET_INS, header, (short) 0, (short) 3) != 0
      ) {
        ISOException.throwIt(ISO7816.SW_LAST_COMMAND_EXPECTED);
      }
    } else {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    short received = apdu.setIncomingAndReceive();
    short length = apdu.getIncomingLength();

    if (
      apdu.getOffsetCdata() != ISO7816.OFFSET_CDATA ||
      length == 0 ||
      length > 255 ||
      !reader.receive(apdu, received, (short) 0, cla == CLA_SINGLE)
    ) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    if (cla == CLA_FIRST || cla == CLA_MORE) {
      return false;
    }

    state[0] = 0;
    reader.reset((short) 0, reader.getReceivedLength());
    return true;
  }
}
