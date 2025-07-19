package monoid;

import javacard.framework.*;

public final class Utils {
  public static boolean equal(byte[] a, byte[] b, short bOffset, short bLength) {
    return a.length == bLength && Util.arrayCompare(a, (short) 0, b, bOffset, bLength) == 0;
  }

  public static boolean equal(byte[] a, byte[] b) {
    return a.length == b.length && Util.arrayCompare(a, (short) 0, b, (short) 0, (short) a.length) == 0;
  }

  public static short min(short a, short b) {
    return a < b ? a : b;
  }

  public static byte[] duplicateAsGlobal(byte[] buffer, short offset, short length) {
    byte[] global = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) length);

    Util.arrayCopyNonAtomic(buffer, offset, global, (short) 0, length);

    return global;
  }

  public static byte[] duplicateAsGlobal(byte[] buffer) {
    return duplicateAsGlobal(buffer, (short) 0, (short) buffer.length);
  }
}
