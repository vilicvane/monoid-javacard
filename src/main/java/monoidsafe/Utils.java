package monoidsafe;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public final class Utils {

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
    byte[] duplicate = new byte[buffer.length];

    Util.arrayCopyNonAtomic(buffer, offset, duplicate, (short) 0, length);

    return duplicate;
  }

  public static byte[] duplicateAsPersistent(byte[] buffer) {
    return duplicateAsPersistent(buffer, (short) 0, (short) buffer.length);
  }
}
