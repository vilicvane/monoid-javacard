package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public final class Utils {

  private static final short COPY_LENGTH = 256;

  public static byte[] makePrivateByteArray(short length) {
    return new byte[length];
  }

  public static byte[] duplicateAsPrivate(byte[] source) {
    byte[] duplicate = makePrivateByteArray((short) source.length);
    Util.arrayCopyNonAtomic(source, (short) 0, duplicate, (short) 0, (short) source.length);
    return duplicate;
  }

  public static byte[] duplicateAsPersistent(SafeDataSource source, short length) {
    byte[] duplicate = new byte[length];

    for (short offset = 0; offset < length; ) {
      short copied = min((short) (length - offset), COPY_LENGTH);
      source.read(offset, duplicate, offset, copied);
      offset += copied;
    }

    return duplicate;
  }

  public static void copy(
    SafeDataSource source,
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

  public static void reverse(byte[] buffer, short offset, short length) {
    for (short index = 0; index < (short) (length / 2); index++) {
      short left = (short) (offset + index);
      short right = (short) (offset + length - index - 1);
      byte value = buffer[left];

      buffer[left] = buffer[right];
      buffer[right] = value;
    }
  }

  public static boolean isEqual(byte[] a, byte[] b, short bOffset, short bLength) {
    return (a.length == bLength && Util.arrayCompare(a, (short) 0, b, bOffset, bLength) == 0);
  }

  public static boolean isEqual(byte[] a, byte[] b) {
    return (
      a.length == b.length && Util.arrayCompare(a, (short) 0, b, (short) 0, (short) a.length) == 0
    );
  }

  public static boolean isZero(byte[] buffer, short offset, short length) {
    for (short index = 0; index < length; index++) {
      if (buffer[(short) (offset + index)] != 0) {
        return false;
      }
    }

    return true;
  }

  public static boolean isZero(byte[] buffer) {
    return isZero(buffer, (short) 0, (short) buffer.length);
  }

  public static short min(short a, short b) {
    return a < b ? a : b;
  }

  public static byte[] duplicateAsGlobal(byte[] buffer, short offset, short length) {
    byte[] duplicate = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, length);

    Util.arrayCopyNonAtomic(buffer, offset, duplicate, (short) 0, length);

    return duplicate;
  }

  public static byte[] duplicateAsGlobal(byte[] buffer) {
    return duplicateAsGlobal(buffer, (short) 0, (short) buffer.length);
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
