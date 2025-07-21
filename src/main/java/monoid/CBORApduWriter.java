package monoid;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class CBORApduWriter extends CBORWriter {

  private static final short CHUNK_SIZE = 256;
  private static final short BUFFER_LENGTH_EXTENSION = 256;

  private byte[] buffer;

  protected short sentOffset;

  public CBORApduWriter() {
    buffer = JCSystem.makeTransientByteArray(BUFFER_LENGTH_EXTENSION, JCSystem.CLEAR_ON_DESELECT);

    reset();
  }

  @Override
  protected void write(short offset, byte value) {
    ensureBufferLength((short) (offset + 1));

    buffer[offset] = value;
  }

  @Override
  protected void write(short offset, byte[] data, short dataOffset, short length) {
    ensureBufferLength((short) (offset + length));

    Util.arrayCopyNonAtomic(data, dataOffset, buffer, offset, length);
  }

  private void ensureBufferLength(short length) {
    if (length <= buffer.length) {
      return;
    }

    byte[] extendedBuffer = JCSystem.makeTransientByteArray(
      (short) (buffer.length + BUFFER_LENGTH_EXTENSION),
      JCSystem.CLEAR_ON_DESELECT
    );

    Util.arrayCopyNonAtomic(buffer, (short) 0, extendedBuffer, (short) 0, (short) buffer.length);

    buffer = extendedBuffer;

    JCSystem.requestObjectDeletion();
  }

  protected void reset() {
    super.reset((short) 0);

    sentOffset = 0;
  }

  public void send() {
    APDU apdu = APDU.getCurrentAPDU();

    short length = (short) (offset - sentOffset);
    short sendingLength = Utils.min(length, CHUNK_SIZE);

    apdu.setOutgoing();
    apdu.setOutgoingLength(sendingLength);

    apdu.sendBytesLong(buffer, sentOffset, sendingLength);

    sentOffset += sendingLength;

    short remainingLength = Utils.min((short) (offset - sentOffset), CHUNK_SIZE);

    ISOException.throwIt(
      remainingLength > 0
        ? (short) (ISO7816.SW_BYTES_REMAINING_00 | remainingLength)
        : ISO7816.SW_NO_ERROR
    );
  }
}
