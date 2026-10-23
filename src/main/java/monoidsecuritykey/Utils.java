package monoidsecuritykey;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public final class Utils {

  static byte[] global(byte[] value) {
    byte[] copy = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) value.length);
    Util.arrayCopyNonAtomic(value, (short) 0, copy, (short) 0, (short) value.length);
    return copy;
  }

  static byte[] global(short length) {
    return (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, length);
  }

  static boolean isEqual(byte[] first, byte[] second) {
    return (
      first.length == second.length &&
      Util.arrayCompare(first, (short) 0, second, (short) 0, (short) first.length) == 0
    );
  }
}
