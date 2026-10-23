package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import monoidlib.Utils;

/** Operation-local adapter. Client objects are never retained in persistent fields. */
final class SafeSessionSource extends SafeDataSource {

  private final MonoidSession session;
  private final Object[] source = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );

  SafeSessionSource(MonoidSession session, SafeDataShareable source) {
    if (source == null) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    this.session = session;
    this.source[0] = source;
  }

  @Override
  public short getLength() {
    session.assertActive();
    short length = ((SafeDataShareable) source[0]).getLength();
    session.assertActive();

    if (length < 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    return length;
  }

  @Override
  public void read(short dataOffset, byte[] buffer, short bufferOffset, short length) {
    session.assertActive();
    // Monoid is not the selected applet during this call and cannot obtain the APDU buffer.
    // Match the storage copy's 256-byte chunks to avoid repeated client callbacks.
    byte[] global = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      Utils.min(length, (short) 256)
    );

    while (length > 0) {
      short copied = Utils.min(length, (short) global.length);
      ((SafeDataShareable) source[0]).read(dataOffset, global, (short) 0, copied);
      session.assertActive();
      Util.arrayCopyNonAtomic(global, (short) 0, buffer, bufferOffset, copied);
      dataOffset += copied;
      bufferOffset += copied;
      length -= copied;
    }
  }

  void close() {
    source[0] = null;
  }
}
