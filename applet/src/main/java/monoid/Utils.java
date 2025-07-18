package monoid;

import javacard.framework.*;

public final class Utils {
  public static boolean equal(byte[] a, byte[] b, short bOffset, byte bLength) {
    return a.length == bLength && Util.arrayCompare(a, (short) 0, b, bOffset, bLength) == 0;
  }
}
