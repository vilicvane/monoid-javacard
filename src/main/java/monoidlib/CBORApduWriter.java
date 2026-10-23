package monoidlib;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class CBORApduWriter extends CBORBufferWriter {

  private static final short UNITS_PER_APDU = 4;
  private static final short WINDOW_LENGTH = 64;

  private static final short PENDING = 0;
  private static final short DIRECT_CAPACITY = 1;
  private static final short RESPONSE_LENGTH = 2;
  private static final short RESPONSE_OFFSET = 3;

  private final short[] pending;
  private CBORResponse response;
  private byte[] window;
  private boolean more;

  protected short sentOffset;

  public CBORApduWriter() {
    pending = null;
  }

  public CBORApduWriter(byte[] buffer, short overflowStatus) {
    super(buffer, (short) 0, overflowStatus);
    pending = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
  }

  public boolean hasPending() {
    return buffer != null
      ? pending[RESPONSE_OFFSET] < pending[RESPONSE_LENGTH]
      : sentOffset < state[OFFSET] || more;
  }

  public void start(CBORResponse response, short maxUnitLength) {
    reset();

    this.response = response;
    more = true;

    try {
      // A complete unit may extend beyond the next APDU's payload boundary.
      window = new byte[(short) (CHUNK_LENGTH + maxUnitLength)];
    } catch (RuntimeException e) {
      reset();
      throw e;
    }
  }

  @Override
  public void reset(short offset) {
    super.reset(offset);

    if (pending != null) {
      for (short index = 0; index < pending.length; index++) {
        pending[index] = 0;
      }
    } else {
      sentOffset = offset;
    }
  }

  public void reset(short offset, short directCapacity) {
    reset(offset);
    pending[DIRECT_CAPACITY] = directCapacity;
  }

  public boolean isDirect() {
    return pending != null && pending[DIRECT_CAPACITY] != 0;
  }

  @Override
  protected void write(short offset, byte value) {
    if (window != null) {
      window[offset] = value;
      return;
    }

    if (buffer != null) {
      assertLength(offset, (short) 1);
      if (isDirect()) {
        if (offset < pending[DIRECT_CAPACITY]) {
          APDU.getCurrentAPDUBuffer()[offset] = value;
          return;
        }
        store(offset);
      }
      APDU.getCurrentAPDUBuffer()[pending[PENDING]++] = value;
      if (pending[PENDING] == WINDOW_LENGTH) {
        flush((short) (offset + 1));
      }
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

    if (buffer != null) {
      assertLength(offset, length);
      if (isDirect()) {
        if (offset <= (short) (pending[DIRECT_CAPACITY] - length)) {
          Util.arrayCopyNonAtomic(data, dataOffset, APDU.getCurrentAPDUBuffer(), offset, length);
          return;
        }
        store(offset);
      }
      while (length > 0) {
        short copied = min((short) (WINDOW_LENGTH - pending[PENDING]), length);
        Util.arrayCopyNonAtomic(
          data,
          dataOffset,
          APDU.getCurrentAPDUBuffer(),
          pending[PENDING],
          copied
        );
        pending[PENDING] += copied;
        offset += copied;
        dataOffset += copied;
        length -= copied;
        if (pending[PENDING] == WINDOW_LENGTH) {
          flush(offset);
        }
      }
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
    return new byte[CHUNK_LENGTH];
  }

  private void prepareWrite(short offset, short length) {
    if (chunks[0] != null) {
      return;
    }

    // Commands finish reading their request before writing the response.
    // Borrow the current APDU only for a response that fits in one message.
    byte[] apduBuffer = APDU.getCurrentAPDUBuffer();

    if ((short) (offset + length) <= min(CHUNK_LENGTH, (short) apduBuffer.length)) {
      return;
    }

    Util.arrayCopyNonAtomic(apduBuffer, (short) 0, requireChunk((short) 0), (short) 0, offset);
  }

  @Override
  public short getLength() {
    if (buffer != null) {
      // Finish encoding before sending or accepting another APDU.
      flush(state[OFFSET]);
    }
    return super.getLength();
  }

  public void store() {
    if (isDirect()) {
      store(state[OFFSET]);
    }
  }

  private void store(short length) {
    Util.arrayCopyNonAtomic(APDU.getCurrentAPDUBuffer(), (short) 0, buffer, (short) 0, length);
    pending[DIRECT_CAPACITY] = 0;
  }

  private void flush(short offset) {
    if (pending[PENDING] != 0) {
      Util.arrayCopyNonAtomic(
        APDU.getCurrentAPDUBuffer(),
        (short) 0,
        buffer,
        (short) (offset - pending[PENDING]),
        pending[PENDING]
      );
      pending[PENDING] = 0;
    }
  }

  @Override
  public short copyDataTo(byte[] dest, short destOffset) {
    if (window != null) {
      Util.arrayCopyNonAtomic(window, (short) 0, dest, destOffset, state[OFFSET]);
      return state[OFFSET];
    }

    if ((buffer != null && !isDirect()) || (chunks != null && chunks[0] != null)) {
      return super.copyDataTo(dest, destOffset);
    }

    short length = getLength();

    if (length > 0) {
      Util.arrayCopyNonAtomic(
        APDU.getCurrentAPDUBuffer(),
        (short) (state[OFFSET] - length),
        dest,
        destOffset,
        length
      );
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

    if (chunks != null) {
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
    }

    super.reset();
  }

  /** Sends a dynamic response and releases its storage when complete or interrupted. */
  public void send() {
    boolean pending = false;

    try {
      short status = sendResponse(APDU.getCurrentAPDU());
      pending = hasPending();
      ISOException.throwIt(status);
    } finally {
      if (!pending) {
        reset();
      }
    }
  }

  /** Starts a fixed-buffer response, including any prefix supplied by the caller. */
  public void send(APDU apdu, short length) {
    flush(state[OFFSET]);
    pending[RESPONSE_LENGTH] = length;
    pending[RESPONSE_OFFSET] = 0;
    send(apdu);
  }

  /** Continues a fixed-buffer response, returning normally after its final part. */
  public void send(APDU apdu) {
    short status = sendResponse(apdu);
    if (status != ISO7816.SW_NO_ERROR) {
      ISOException.throwIt(status);
    }
  }

  private short sendResponse(APDU apdu) {
    if (window != null) {
      // The previous send may retain its buffer until that APDU finishes.
      state[OFFSET] -= sentOffset;
      Util.arrayCopyNonAtomic(window, sentOffset, window, (short) 0, state[OFFSET]);
      sentOffset = 0;

      // Return to the runtime between batches so temporary item views can be reclaimed.
      for (short unit = 0; unit < UNITS_PER_APDU && more && state[OFFSET] < CHUNK_LENGTH; unit++) {
        more = response.writeNext(this);
      }
    }

    short offset = buffer != null ? pending[RESPONSE_OFFSET] : sentOffset;
    short remaining = (short) ((buffer != null ? pending[RESPONSE_LENGTH] : state[OFFSET]) -
      offset);
    if (buffer != null && remaining == 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    short expected = apdu.setOutgoing();
    short capacity = CHUNK_LENGTH;
    if (buffer != null) {
      // Extended requests can receive the complete fixed response without GET RESPONSE.
      capacity = expected > 0 ? expected : CHUNK_LENGTH;
    } else if (window != null && expected > 0) {
      capacity = min(CHUNK_LENGTH, expected);
    }
    short length = min(remaining, capacity);
    apdu.setOutgoingLength(length);

    if (window != null) {
      apdu.sendBytesLong(window, offset, length);
    } else if (buffer != null) {
      if (isDirect() && length == remaining) {
        apdu.sendBytes(offset, length);
      } else {
        // GET RESPONSE replaces the APDU buffer; own a borrowed reply before its first part.
        store();
        apdu.sendBytesLong(buffer, offset, length);
      }
    } else if (chunks[0] != null) {
      apdu.sendBytesLong(
        (byte[]) chunks[(short) (offset / CHUNK_LENGTH)],
        (short) (offset % CHUNK_LENGTH),
        length
      );
    } else {
      apdu.sendBytes(offset, length);
    }

    remaining -= length;
    if (buffer != null) {
      pending[RESPONSE_OFFSET] += length;
      if (remaining == 0) {
        pending[RESPONSE_OFFSET] = 0;
        pending[RESPONSE_LENGTH] = 0;
      }
    } else {
      sentOffset += length;
    }

    return hasPending()
      ? (short) (ISO7816.SW_BYTES_REMAINING_00 |
        (more || remaining >= CHUNK_LENGTH ? 0 : remaining))
      : ISO7816.SW_NO_ERROR;
  }
}
