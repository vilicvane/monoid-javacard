package monoid;

import javacard.framework.APDU;
import javacard.framework.ISO7816;

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
