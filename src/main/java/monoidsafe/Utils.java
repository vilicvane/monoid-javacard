package monoidsafe;

import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;

public final class Utils {

  private static final short COPY_BUFFER_LENGTH = 256;
  private static final short TRANSIENT_BUFFER_LENGTH = 512;

  public static byte[] makePrivateByteArray(short length) {
    if (length <= TRANSIENT_BUFFER_LENGTH) {
      try {
        return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_RESET);
      } catch (SystemException e) {
        if (e.getReason() != SystemException.NO_TRANSIENT_SPACE) {
          throw e;
        }
      }
    }

    return new byte[length];
  }

  public static byte[] duplicateAsPrivate(byte[] source) {
    byte[] duplicate = makePrivateByteArray((short) source.length);
    Util.arrayCopyNonAtomic(source, (short) 0, duplicate, (short) 0, (short) source.length);
    return duplicate;
  }

  public static byte[] duplicateAsPersistent(SafeDataShareable source, short length) {
    byte[] duplicate = new byte[length];

    if (length > 0) {
      byte[] buffer = (byte[]) JCSystem.makeGlobalArray(
        JCSystem.ARRAY_TYPE_BYTE,
        length < COPY_BUFFER_LENGTH ? length : COPY_BUFFER_LENGTH
      );
      copy(source, (short) 0, duplicate, (short) 0, length, buffer);
    }

    return duplicate;
  }

  public static void copy(
    SafeDataShareable source,
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

  public static byte[] duplicateAsGlobal(byte[] buffer, short offset, short length) {
    byte[] duplicate = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, length);

    Util.arrayCopyNonAtomic(buffer, offset, duplicate, (short) 0, length);

    return duplicate;
  }

  public static byte[] duplicateAsGlobal(byte[] buffer) {
    return duplicateAsGlobal(buffer, (short) 0, (short) buffer.length);
  }

  public static byte[] duplicateAsTransientDeselect(byte[] buffer, short offset, short length) {
    byte[] duplicate = JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);

    Util.arrayCopyNonAtomic(buffer, offset, duplicate, (short) 0, length);

    return duplicate;
  }

  public static byte[] duplicateAsTransientDeselect(byte[] buffer) {
    return duplicateAsTransientDeselect(buffer, (short) 0, (short) buffer.length);
  }

  public static byte[] duplicateAsPersistent(byte[] buffer, short offset, short length) {
    byte[] duplicate = new byte[length];

    Util.arrayCopyNonAtomic(buffer, offset, duplicate, (short) 0, length);

    return duplicate;
  }

  public static byte[] duplicateAsPersistent(byte[] buffer) {
    return duplicateAsPersistent(buffer, (short) 0, (short) buffer.length);
  }
}
