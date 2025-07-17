package monoid;

import javacard.framework.*;

public class CBORApduReader extends CBORReader {
  public CBORApduReader() {
    reset();
  }

  @Override
  protected byte[] getBuffer() {
    return APDU.getCurrentAPDUBuffer();
  }

  protected void reset() {
    super.reset(ISO7816.OFFSET_CDATA);
  }
}
