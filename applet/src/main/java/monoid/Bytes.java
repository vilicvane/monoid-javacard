package monoid;

import javacard.security.*;

public final class Bytes {
  public static byte compare(byte[] a, short aOffset, byte[] b, short bOffset, short length) {
    for (short index = 0; index < length; index++) {
      short aShort = (short) (a[(short) (aOffset + index)] & 0xFF);
      short bShort = (short) (b[(short) (bOffset + index)] & 0xFF);

      if (aShort > bShort) {
        return 1;
      } else if (aShort < bShort) {
        return -1;
      }
    }

    return 0;
  }

  public static short add(byte[] a, short aOff, byte[] b, short bOff, byte[] out, short outOff, short length) {
    short regrouped = 0;
    for (short index = (short) (length - 1); index >= 0; index--) {
      regrouped = (short) ((short) (a[(short) (aOff + index)] & 0xFF) + (short) (b[(short) (bOff + index)] & 0xFF)
          + regrouped);

      out[(short) (outOff + index)] = (byte) regrouped;

      regrouped = (short) (regrouped >> 8);
    }
    return regrouped;
  }

  public static void sub(byte[] a, short aOffset, byte[] b, short bOffset, byte[] out, short outOffset,
      short length) {
    short regrouped = 0;

    for (short index = (short) (length - 1); index >= 0; index--) {
      regrouped = (short) ((short) (a[(short) (aOffset + index)] & 0xFF) - (short) (b[(short) (bOffset + index)] & 0xFF)
          - regrouped);

      out[(short) (outOffset + index)] = (byte) regrouped;

      regrouped = (short) (((regrouped >> 8) != 0) ? 1 : 0);
    }

    if (regrouped != 0) {
      throw new CryptoException(CryptoException.ILLEGAL_VALUE);
    }
  }
}
