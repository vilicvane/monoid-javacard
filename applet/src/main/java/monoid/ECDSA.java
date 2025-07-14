package monoid;

public final class ECDSA {
  final static private byte[] HALF_N = {
      (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0x5D, (byte) 0x57, (byte) 0x6E, (byte) 0x73, (byte) 0x57, (byte) 0xA4, (byte) 0x50, (byte) 0x1D,
      (byte) 0xDF, (byte) 0xE9, (byte) 0x2F, (byte) 0x46, (byte) 0x68, (byte) 0x1B, (byte) 0x20, (byte) 0xA0 };

  final static private byte[] N = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE,
      (byte) 0xBA, (byte) 0xAE, (byte) 0xDC, (byte) 0xE6, (byte) 0xAF, (byte) 0x48, (byte) 0xA0, (byte) 0x3B,
      (byte) 0xBF, (byte) 0xD2, (byte) 0x5E, (byte) 0x8C, (byte) 0xD0, (byte) 0x36, (byte) 0x41, (byte) 0x41 };

  public static void ensureLowS(byte[] signature, short offset) {
    short sOffset = (short) (offset + N.length);

    if (bytesCompare(signature, sOffset, HALF_N, (short) 0, (short) HALF_N.length) > 0) {
      bytesSub(N, (short) 0, signature, sOffset, signature, sOffset, (short) N.length);
    }
  }

  private static byte bytesCompare(byte[] a, short aOffset, byte[] b, short bOffset, short length) {
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

  private static void bytesSub(byte[] a, short aOffset, byte[] b, short bOffset, byte[] out, short outOffset,
      short length) {
    short regrouped = 0;

    for (short index = (short) (length - 1); index >= 0; index--) {
      regrouped = (short) ((short) (a[(short) (aOffset + index)] & 0xFF) - (short) (b[(short) (bOffset + index)] & 0xFF)
          - regrouped);

      out[(short) (outOffset + index)] = (byte) regrouped;

      regrouped = (short) (((regrouped >> 8) != 0) ? 1 : 0);
    }
  }
}
