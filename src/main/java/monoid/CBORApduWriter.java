package monoid;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class CBORApduWriter extends CBORBufferWriter {

  private static final short CHUNK_SIZE = 256;

  protected short sentOffset;

  public boolean hasPending() {
    return sentOffset < offset;
  }

  @Override
  protected void write(short offset, byte value) {
    requireBuffer(offset, (short) 1)[offset] = value;
  }

  @Override
  protected void write(short offset, byte[] data, short dataOffset, short length) {
    Util.arrayCopyNonAtomic(data, dataOffset, requireBuffer(offset, length), offset, length);
  }

  private byte[] requireBuffer(short offset, short length) {
    short requiredLength = (short) (offset + length);

    if (buffer != null) {
      ensureBufferLength(requiredLength);
      return buffer;
    }

    // Commands finish reading their request before writing the response.
    // Borrow the current APDU only for a response that fits in one message.
    byte[] apduBuffer = APDU.getCurrentAPDUBuffer();

    if (requiredLength <= Utils.min(CHUNK_SIZE, (short) apduBuffer.length)) {
      return apduBuffer;
    }

    ensureBufferLength(requiredLength);
    Util.arrayCopyNonAtomic(apduBuffer, (short) 0, buffer, (short) 0, offset);

    return buffer;
  }

  @Override
  public short copyDataTo(byte[] dest, short destOffset) {
    short length = getLength();

    if (length > 0) {
      Util.arrayCopyNonAtomic(
        buffer != null ? buffer : APDU.getCurrentAPDUBuffer(),
        (short) 0,
        dest,
        destOffset,
        length
      );
    }

    return length;
  }

  @Override
  public void reset() {
    if (buffer != null) {
      buffer = null;
      JCSystem.requestObjectDeletion();
    }

    super.reset();

    sentOffset = offset;
  }

  public void send() {
    boolean pending = false;

    try {
      APDU apdu = APDU.getCurrentAPDU();

      short length = (short) (offset - sentOffset);
      short sendingLength = Utils.min(length, CHUNK_SIZE);

      apdu.setOutgoing();
      apdu.setOutgoingLength(sendingLength);

      if (buffer != null) {
        apdu.sendBytesLong(buffer, sentOffset, sendingLength);
      } else {
        apdu.sendBytes(sentOffset, sendingLength);
      }

      sentOffset += sendingLength;

      short remainingLength = Utils.min((short) (offset - sentOffset), CHUNK_SIZE);
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
