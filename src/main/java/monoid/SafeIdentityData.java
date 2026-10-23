package monoid;

import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import monoididentity.CommunicationDataShareable;
import monoidlib.Utils;

final class SafeIdentityData extends SafeDataSource {

  private final Safe safe;
  private final CommunicationDataShareable data;

  SafeIdentityData(Safe safe, CommunicationDataShareable data) {
    this.safe = safe;
    this.data = data;
  }

  @Override
  public short getLength() {
    safe.assertAccess();

    return data.getLength();
  }

  @Override
  public void read(short dataOffset, byte[] dest, short offset, short length) {
    safe.assertAccess();

    // The APDU buffer is already global and can cross the Identity firewall directly.
    if (dest == APDU.getCurrentAPDUBuffer()) {
      data.read(dataOffset, dest, offset, length);

      return;
    }

    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      Utils.min(length, (short) 64)
    );

    while (length > 0) {
      short copied = Utils.min(length, (short) buffer.length);

      data.read(dataOffset, buffer, (short) 0, copied);
      Util.arrayCopyNonAtomic(buffer, (short) 0, dest, offset, copied);

      dataOffset += copied;
      offset += copied;
      length -= copied;
    }
  }
}
