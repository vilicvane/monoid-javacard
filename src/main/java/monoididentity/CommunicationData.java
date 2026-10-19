package monoididentity;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/** A completed result that only its original caller may read. */
public final class CommunicationData implements CommunicationDataShareable {

  private final byte[] data;
  private final AID caller;

  CommunicationData(byte[] data, AID caller) {
    this.data = data;
    this.caller = caller;
  }

  @Override
  public short getLength() {
    assertCaller();

    return (short) data.length;
  }

  @Override
  public void read(short dataOffset, byte[] buffer, short offset, short length) {
    assertCaller();

    Util.arrayCopyNonAtomic(data, dataOffset, buffer, offset, length);
  }

  private void assertCaller() {
    if (caller != JCSystem.getPreviousContextAID()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  static byte[] makePrivateByteArray(short length) {
    return new byte[length];
  }

  static byte[] duplicateAsPrivate(byte[] value) {
    if (value == null) {
      return null;
    }

    byte[] copy = makePrivateByteArray((short) value.length);
    Util.arrayCopyNonAtomic(value, (short) 0, copy, (short) 0, (short) value.length);

    return copy;
  }

  static void copy(
    CommunicationDataShareable source,
    short sourceOffset,
    byte[] dest,
    short offset,
    short length,
    byte[] buffer
  ) {
    while (length > 0) {
      short copied = length < buffer.length ? length : (short) buffer.length;
      source.read(sourceOffset, buffer, (short) 0, copied);
      Util.arrayCopyNonAtomic(buffer, (short) 0, dest, offset, copied);
      sourceOffset += copied;
      offset += copied;
      length -= copied;
    }
  }
}
