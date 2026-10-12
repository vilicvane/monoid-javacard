package monoid;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class CBORApduReader extends CBORReader {

  public static final short MAX_LENGTH = 8192;

  private static final short CHUNK_LENGTH = 256;
  private static final short TRANSIENT_LENGTH = 512;

  public static final byte CLA_SINGLE = 0x00;
  public static final byte CLA_FIRST = (byte) 0x90;
  public static final byte CLA_MORE = (byte) 0xB0;
  public static final byte CLA_LAST = (byte) 0xA0;

  private static final short RECEIVING = 1;
  private static final short READY = 2;

  private final byte[] header = JCSystem.makeTransientByteArray(
    (short) 3,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final short[] state = JCSystem.makeTransientShortArray(
    (short) 2,
    JCSystem.CLEAR_ON_DESELECT
  );

  // Keep persistent chunks reachable for release after reset clears the state.
  private final Object[] chunks = new Object[MAX_LENGTH / CHUNK_LENGTH];

  public CBORApduReader() {
    reset();
  }

  @Override
  protected short getLength() {
    return state[0] == READY ? state[1] : (short) 0;
  }

  @Override
  public byte[] getChunk(short offset) {
    if (state[0] != READY) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    return chunks[0] != null
      ? (byte[]) chunks[(short) (offset / CHUNK_LENGTH)]
      : APDU.getCurrentAPDUBuffer();
  }

  @Override
  public short getChunkOffset(short offset) {
    return chunks[0] != null
      ? (short) (offset % CHUNK_LENGTH)
      : (short) (ISO7816.OFFSET_CDATA + offset);
  }

  @Override
  public short getChunkLength(short offset) {
    short remaining = (short) (getLength() - offset);
    short chunkLength = (short) (CHUNK_LENGTH - (short) (offset % CHUNK_LENGTH));

    return chunks[0] != null && chunkLength < remaining ? chunkLength : remaining;
  }

  protected boolean isReceiving() {
    return state[0] == RECEIVING;
  }

  protected boolean receive() {
    boolean accepted = false;

    try {
      boolean complete = receiveFrame();
      accepted = true;
      return complete;
    } finally {
      if (!accepted) {
        clear();
      }
    }
  }

  private boolean receiveFrame() {
    APDU apdu = APDU.getCurrentAPDU();
    byte[] incoming = apdu.getBuffer();
    byte cla = incoming[ISO7816.OFFSET_CLA];

    if (cla == CLA_SINGLE || cla == CLA_FIRST) {
      boolean replaced = chunks[0] != null;
      clear();

      if (replaced) {
        JCSystem.requestObjectDeletion();
      }

      Util.arrayCopyNonAtomic(incoming, ISO7816.OFFSET_INS, header, (short) 0, (short) 3);

      if (cla == CLA_FIRST) {
        state[0] = RECEIVING;
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

    if (apdu.getOffsetCdata() != ISO7816.OFFSET_CDATA || length == 0 || length > 255) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    if (cla == CLA_SINGLE && received == length) {
      state[0] = READY;
      state[1] = length;
      return true;
    }

    if (length > (short) (MAX_LENGTH - state[1])) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    short offset = 0;
    short dataOffset = ISO7816.OFFSET_CDATA;

    while (true) {
      if (received < 0 || received > (short) (length - offset)) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }

      append(incoming, dataOffset, received);

      offset += received;

      if (offset == length) {
        break;
      }

      dataOffset = 0;
      received = apdu.receiveBytes(dataOffset);

      if (received == 0) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
    }

    if (cla == CLA_FIRST || cla == CLA_MORE) {
      return false;
    }

    state[0] = READY;
    return true;
  }

  private void append(byte[] incoming, short offset, short length) {
    while (length > 0) {
      short chunkIndex = (short) (state[1] / CHUNK_LENGTH);
      short chunkOffset = (short) (state[1] % CHUNK_LENGTH);
      short chunkLength = (short) (CHUNK_LENGTH - chunkOffset);

      if (chunkLength > length) {
        chunkLength = length;
      }

      byte[] chunk = (byte[]) chunks[chunkIndex];

      if (chunk == null) {
        chunk = chunkIndex < TRANSIENT_LENGTH / CHUNK_LENGTH
          ? JCSystem.makeTransientByteArray(CHUNK_LENGTH, JCSystem.CLEAR_ON_DESELECT)
          : new byte[CHUNK_LENGTH];
        chunks[chunkIndex] = chunk;
      }

      Util.arrayCopyNonAtomic(incoming, offset, chunk, chunkOffset, chunkLength);

      state[1] += chunkLength;
      offset += chunkLength;
      length -= chunkLength;
    }
  }

  protected void clear() {
    state[0] = 0;
    state[1] = 0;

    for (short index = 0; index < chunks.length; index++) {
      if (chunks[index] != null) {
        chunks[index] = null;
      }
    }
  }

  protected void reset() {
    super.reset((short) 0);
  }
}
