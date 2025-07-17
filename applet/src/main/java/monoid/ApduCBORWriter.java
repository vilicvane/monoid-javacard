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
}
