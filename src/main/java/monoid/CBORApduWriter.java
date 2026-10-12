package monoid;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class CBORApduWriter extends CBORBufferWriter {

  private static final short CHUNK_SIZE = 256;

  protected short sentOffset;

  public boolean hasPending() {
    return sentOffset < offset;
  }

  @Override
  public void reset() {
    Util.arrayFillNonAtomic(buffer, (short) 0, (short) buffer.length, (byte) 0);

    super.reset();

    sentOffset = offset;
  }

  public void send() {
    APDU apdu = APDU.getCurrentAPDU();

    short length = (short) (offset - sentOffset);
    short sendingLength = Utils.min(length, CHUNK_SIZE);

    apdu.setOutgoing();
    apdu.setOutgoingLength(sendingLength);

    apdu.sendBytesLong(buffer, sentOffset, sendingLength);

    Util.arrayFillNonAtomic(buffer, sentOffset, sendingLength, (byte) 0);

    sentOffset += sendingLength;

    short remainingLength = Utils.min((short) (offset - sentOffset), CHUNK_SIZE);

    ISOException.throwIt(
      remainingLength > 0
        ? (short) (ISO7816.SW_BYTES_REMAINING_00 | remainingLength)
        : ISO7816.SW_NO_ERROR
    );
  }
}
