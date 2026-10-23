package monoid;

public final class LibECDSA {

  public static void ensureLowS(byte[] order, byte[] signature, short offset) {
    short length = (short) order.length;
    short sOffset = (short) (offset + length);
    short carry = 0;

    // Compare with floor(order / 2) without allocating and writing a temporary scalar.
    for (short index = 0; index < length; index++) {
      short current = (short) (order[index] & 0xFF);
      short half = (short) ((current >> 1) | carry);
      short s = (short) (signature[(short) (sOffset + index)] & 0xFF);

      if (s != half) {
        if (s > half) {
          LibMath.sub(order, (short) 0, signature, sOffset, signature, sOffset, length);
        }
        return;
      }

      carry = (short) ((current & 1) << 7);
    }
  }
}
