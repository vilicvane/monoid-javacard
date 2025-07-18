package monoid;

import javacard.framework.*;

public class CBORApduWriter extends CBORWriter {
  public CBORApduWriter() {
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
    APDU.getCurrentAPDU().setOutgoingAndSend((short) 0, getLength());
    ISOException.throwIt(ISO7816.SW_NO_ERROR);
  }
}
