package monoidotp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

final class LibTOTP {

  static void counter(byte[] time, short period, byte[] dest, short offset) {
    short remainder = 0;

    for (short index = 0; index < 8; index++) {
      short value = (short) (time[index] & 0xFF);
      short quotient = 0;

      for (short bit = 7; bit >= 0; bit--) {
        remainder = (short) ((remainder << 1) | ((value >> bit) & 1));
        quotient <<= 1;

        if (remainder < 0 || remainder >= period) {
          remainder -= period;
          quotient |= 1;
        }
      }

      dest[(short) (offset + index)] = (byte) quotient;
    }
  }

  static void increment(byte[] counter, short offset) {
    for (short index = 7; index >= 0; index--) {
      short position = (short) (offset + index);
      counter[position]++;

      if (counter[position] != 0) {
        return;
      }
    }

    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
  }

  static void truncate(byte[] hash, short length, byte digits, byte[] output, byte[] value) {
    short offset = (short) (hash[(short) (length - 1)] & 0x0F);
    Util.arrayCopyNonAtomic(hash, offset, value, (short) 0, (short) 4);
    value[0] &= 0x7F;

    for (short digit = (short) (digits - 1); digit >= 0; digit--) {
      short remainder = 0;

      for (short index = 0; index < 4; index++) {
        short next = (short) ((remainder << 8) | (value[index] & 0xFF));
        value[index] = (byte) (next / 10);
        remainder = (short) (next % 10);
      }

      output[digit] = (byte) ('0' + remainder);
    }
  }
}
