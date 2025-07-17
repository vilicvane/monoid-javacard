package monoid;

import javacard.framework.*;

public class ApduCBORWriter extends CBORWriter {
  public ApduCBORWriter() {
    reset();
  }

  @Override
  protected byte[] getBuffer() {
    return APDU.getCurrentAPDUBuffer();
  }

  protected void reset() {
    super.reset((short) 0);
  }

  public void send() {
    APDU.getCurrentAPDU().setOutgoingAndSend((short) 0, (short) getLength());
    ISOException.throwIt(ISO7816.SW_NO_ERROR);
  }
}
