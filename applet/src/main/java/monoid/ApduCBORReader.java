package monoid;

import javacard.framework.*;

public class ApduCBORReader extends CBORReader {
  public ApduCBORReader() {
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
