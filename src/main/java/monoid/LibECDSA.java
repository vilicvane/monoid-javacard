package monoid;

import javacard.framework.JCSystem;

public final class LibECDSA {

  public static void ensureLowS(byte[] order, byte[] signature, short offset) {
    short length = (short) order.length;
    short sOffset = (short) (offset + length);
    byte[] halfOrder = JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_RESET);

    LibMath.shiftRight(order, (short) 0, halfOrder, (short) 0, length, (short) 1, (short) 0);

    if (LibMath.compare(signature, sOffset, halfOrder, (short) 0, length) > 0) {
      LibMath.sub(order, (short) 0, signature, sOffset, signature, sOffset, length);
    }
  }
}
