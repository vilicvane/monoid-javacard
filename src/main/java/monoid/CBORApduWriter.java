package monoid;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class CBORApduWriter extends CBORBufferWriter {

  private static final short TRANSIENT_LENGTH = 512;
  private static final short UNITS_PER_APDU = 4;

  private CBORResponse response;
  private byte[] window;
  private boolean more;

  protected short sentOffset;

  public boolean hasPending() {
    return sentOffset < offset || more;
  }

  public void start(CBORResponse response, short maxUnitLength) {
    reset();

    this.response = response;
    more = true;

    try {
      // A complete unit may extend beyond the next APDU's payload boundary.
      window = JCSystem.makeTransientByteArray(
        (short) (CHUNK_LENGTH + maxUnitLength),
        JCSystem.CLEAR_ON_DESELECT
      );
    } catch (RuntimeException e) {
      reset();
      throw e;
    }
  }

  @Override
  protected void write(short offset, byte value) {
    if (window != null) {
      window[offset] = value;
      return;
    }

    prepareWrite(offset, (short) 1);

    if (chunks[0] != null) {
      super.write(offset, value);
    } else {
      APDU.getCurrentAPDUBuffer()[offset] = value;
    }
  }

  @Override
  protected void write(short offset, byte[] data, short dataOffset, short length) {
    if (window != null) {
      Util.arrayCopyNonAtomic(data, dataOffset, window, offset, length);
      return;
    }

    prepareWrite(offset, length);

    if (chunks[0] != null) {
      super.write(offset, data, dataOffset, length);
    } else {
      Util.arrayCopyNonAtomic(data, dataOffset, APDU.getCurrentAPDUBuffer(), offset, length);
    }
  }

  @Override
  protected byte[] createChunk(short index) {
    return index < TRANSIENT_LENGTH / CHUNK_LENGTH
      ? super.createChunk(index)
      : new byte[CHUNK_LENGTH];
  }

  private void prepareWrite(short offset, short length) {
    if (chunks[0] != null) {
      return;
    }

    // Commands finish reading their request before writing the response.
    // Borrow the current APDU only for a response that fits in one message.
    byte[] apduBuffer = APDU.getCurrentAPDUBuffer();

    if ((short) (offset + length) <= Utils.min(CHUNK_LENGTH, (short) apduBuffer.length)) {
      return;
    }

    Util.arrayCopyNonAtomic(apduBuffer, (short) 0, requireChunk((short) 0), (short) 0, offset);
  }

  @Override
  public short copyDataTo(byte[] dest, short destOffset) {
    if (window != null) {
      Util.arrayCopyNonAtomic(window, (short) 0, dest, destOffset, offset);
      return offset;
    }

    if (chunks[0] != null) {
      return super.copyDataTo(dest, destOffset);
    }

    short length = getLength();

    if (length > 0) {
      Util.arrayCopyNonAtomic(APDU.getCurrentAPDUBuffer(), (short) 0, dest, destOffset, length);
    }

    return length;
  }

  @Override
  public void reset() {
    CBORResponse previous = response;
    response = null;
    window = null;
    more = false;

    if (previous != null) {
      previous.reset();
      JCSystem.requestObjectDeletion();
    }

    short length = 0;

    while (length < chunks.length && chunks[length] != null) {
      length++;
    }

    if (length > 0) {
      // Release from the end so a reset cannot leave gaps between retained chunks.
      while (length > 0) {
        chunks[--length] = null;
      }

      JCSystem.requestObjectDeletion();
    }

    super.reset();

    sentOffset = offset;
  }

  public void send() {
    boolean pending = false;

    try {
      if (window != null) {
        // The previous send may retain its buffer until that APDU finishes.
        offset -= sentOffset;
        Util.arrayCopyNonAtomic(window, sentOffset, window, (short) 0, offset);
        sentOffset = 0;

        // Return to the runtime between batches so temporary item views can be reclaimed.
        for (short unit = 0; unit < UNITS_PER_APDU && more && offset < CHUNK_LENGTH; unit++) {
          more = response.writeNext(this);
        }

        APDU apdu = APDU.getCurrentAPDU();
        short expectedLength = apdu.setOutgoing();
        short sendingLength = Utils.min(
          offset,
          expectedLength > 0 ? Utils.min(CHUNK_LENGTH, expectedLength) : CHUNK_LENGTH
        );
        apdu.setOutgoingLength(sendingLength);
        apdu.sendBytesLong(window, (short) 0, sendingLength);

        sentOffset = sendingLength;

        short remainingLength = more ? 0 : Utils.min((short) (offset - sentOffset), CHUNK_LENGTH);
        pending = hasPending();

        ISOException.throwIt(
          pending ? (short) (ISO7816.SW_BYTES_REMAINING_00 | remainingLength) : ISO7816.SW_NO_ERROR
        );
      }

      APDU apdu = APDU.getCurrentAPDU();

      short length = (short) (offset - sentOffset);
      short sendingLength = Utils.min(length, CHUNK_LENGTH);

      apdu.setOutgoing();
      apdu.setOutgoingLength(sendingLength);

      if (chunks[0] != null) {
        apdu.sendBytesLong(
          (byte[]) chunks[(short) (sentOffset / CHUNK_LENGTH)],
          (short) (sentOffset % CHUNK_LENGTH),
          sendingLength
        );
      } else {
        apdu.sendBytes(sentOffset, sendingLength);
      }

      sentOffset += sendingLength;

      short remainingLength = Utils.min((short) (offset - sentOffset), CHUNK_LENGTH);
      pending = remainingLength > 0;

      ISOException.throwIt(
        pending ? (short) (ISO7816.SW_BYTES_REMAINING_00 | remainingLength) : ISO7816.SW_NO_ERROR
      );
    } finally {
      if (!pending) {
        reset();
      }
    }
  }
}
