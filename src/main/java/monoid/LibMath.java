package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;

/** Initialize shared modular-arithmetic resources before use. */
public final class LibMath {

  private static final byte[] TWO = { 2 };
  private static final short MAX_LENGTH = 32;
  private static final short EXPONENT_BITS = 512;
  private static final short EXPONENT_LENGTH = EXPONENT_BITS / 8;

  private static RSAPrivateKey sharedExponentiationKey;
  private static Cipher sharedExponentiationCipher;
  private static byte[] sharedExponentiationBuffer;
  private static byte[] sharedTemporaryA;
  private static byte[] sharedTemporaryB;
  private static byte[] sharedExponent;

  public static void init() {
    sharedExponentiationKey = (RSAPrivateKey) KeyBuilder.buildKey(
      KeyBuilder.TYPE_RSA_PRIVATE,
      EXPONENT_BITS,
      false
    );
    sharedExponentiationCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    sharedExponentiationBuffer = JCSystem.makeTransientByteArray(
      EXPONENT_LENGTH,
      JCSystem.CLEAR_ON_DESELECT
    );
    sharedTemporaryA = JCSystem.makeTransientByteArray(MAX_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    sharedTemporaryB = JCSystem.makeTransientByteArray(MAX_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    sharedExponent = JCSystem.makeTransientByteArray(MAX_LENGTH, JCSystem.CLEAR_ON_DESELECT);
  }

  public static void dispose() {
    sharedExponentiationKey = null;
    sharedExponentiationCipher = null;
    sharedExponentiationBuffer = null;
    sharedTemporaryA = null;
    sharedTemporaryB = null;
    sharedExponent = null;
  }

  /**
   * Shifts an unsigned big-endian value right by 0-7 bits. Carry is already aligned
   * for the high byte. Output may use the same array and offset as the input.
   */
  public static void shiftRight(
    byte[] value,
    short offset,
    byte[] out,
    short outOffset,
    short length,
    short bits,
    short carry
  ) {
    short mask = (short) ((1 << bits) - 1);

    for (short index = 0; index < length; index++) {
      short current = (short) (value[(short) (offset + index)] & 0xFF);

      out[(short) (outOffset + index)] = (byte) ((current >> bits) | carry);
      carry = (short) ((current & mask) << (8 - bits));
    }
  }

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

  public static short add(
    byte[] a,
    short aOff,
    byte[] b,
    short bOff,
    byte[] out,
    short outOff,
    short length
  ) {
    short regrouped = 0;

    for (short index = (short) (length - 1); index >= 0; index--) {
      regrouped = (short) ((short) (a[(short) (aOff + index)] & 0xFF) +
        (short) (b[(short) (bOff + index)] & 0xFF) +
        regrouped);

      out[(short) (outOff + index)] = (byte) regrouped;

      regrouped = (short) (regrouped >> 8);
    }

    return regrouped;
  }

  public static short sub(
    byte[] a,
    short aOffset,
    byte[] b,
    short bOffset,
    byte[] out,
    short outOffset,
    short length
  ) {
    short regrouped = 0;

    for (short index = (short) (length - 1); index >= 0; index--) {
      regrouped = (short) ((short) (a[(short) (aOffset + index)] & 0xFF) -
        (short) (b[(short) (bOffset + index)] & 0xFF) -
        regrouped);

      out[(short) (outOffset + index)] = (byte) regrouped;

      regrouped = (short) (((regrouped >> 8) != 0) ? 1 : 0);
    }

    return regrouped;
  }

  /**
   * Reduces an unsigned big-endian value to a fixed-width remainder. The modulus
   * is nonzero and at most 32 bytes; input may be up to 64 bytes. Output may
   * overlap the input, but must not overlap the modulus.
   */
  public static void mod(
    byte[] in,
    short inOffset,
    short inLength,
    byte[] modulus,
    short modulusOffset,
    short length,
    byte[] out,
    short outOffset
  ) {
    mod(
      in,
      inOffset,
      inLength,
      modulus,
      modulusOffset,
      length,
      out,
      outOffset,
      sharedExponentiationBuffer
    );
  }

  private static void mod(
    byte[] in,
    short inOffset,
    short inLength,
    byte[] modulus,
    short modulusOffset,
    short length,
    byte[] out,
    short outOffset,
    byte[] remainder
  ) {
    short modulusLength = length;

    Util.arrayCopyNonAtomic(in, inOffset, remainder, (short) 0, inLength);

    while (modulus[modulusOffset] == 0) {
      modulusOffset++;
      modulusLength--;
    }

    short first = (short) (modulus[modulusOffset] & 0xFF);
    short normalization = (short) (leadingZeroBits((short) (first + 1)) - 1);
    byte second = modulusLength > 1 ? modulus[(short) (modulusOffset + 1)] : 0;
    byte third = modulusLength > 2 ? modulus[(short) (modulusOffset + 2)] : 0;
    short shift = (short) (inLength - modulusLength);
    short round = 0;

    while (shift >= 0) {
      short start = (short) (round > 0 ? round - 1 : 0);

      while (
        compareShifted(remainder, inLength, modulus, modulusOffset, modulusLength, shift, start) >=
        0
      ) {
        short dividend = round == 0 ? 0 : (short) (remainder[(short) (round - 1)] << 8);
        dividend |= (short) (remainder[round] & 0xFF);
        short divisor;

        if (dividend < 0) {
          dividend = (short) ((dividend >>> 1) & 0x7FFF);
          divisor = (short) (first >> 1);
        } else {
          short bitShift = (short) (leadingZeroBits(dividend) - 1);

          if (bitShift > normalization) {
            bitShift = normalization;
          }

          dividend = shiftHighDigits(
            dividend,
            round < (short) (inLength - 1) ? remainder[(short) (round + 1)] : 0,
            round < (short) (inLength - 2) ? remainder[(short) (round + 2)] : 0,
            bitShift
          );
          divisor = shiftHighDigits(first, second, third, bitShift);
        }

        // Round the divisor up to keep the estimate below the true quotient.
        // The comparison above permits a single subtraction if it rounds to 0.
        short multiple = (short) (dividend / (short) (divisor + 1));

        if (multiple < 1) {
          multiple = 1;
        }

        subtractShiftedMultiple(
          remainder,
          inLength,
          modulus,
          modulusOffset,
          modulusLength,
          shift,
          multiple
        );
      }

      round++;
      shift--;
    }

    short resultLength = inLength < length ? inLength : length;

    Util.arrayFillNonAtomic(out, outOffset, (short) (length - resultLength), (byte) 0);
    Util.arrayCopyNonAtomic(
      remainder,
      (short) (inLength - resultLength),
      out,
      (short) (outOffset + length - resultLength),
      resultLength
    );
  }

  private static byte compareShifted(
    byte[] value,
    short valueLength,
    byte[] divisor,
    short divisorOffset,
    short divisorLength,
    short shift,
    short start
  ) {
    short divisorStart = (short) (valueLength - divisorLength - shift);
    short divisorEnd = (short) (valueLength - shift);

    for (short index = start; index < valueLength; index++) {
      short a = (short) (value[index] & 0xFF);
      short b = index >= divisorStart && index < divisorEnd
        ? (short) (divisor[(short) (divisorOffset + index - divisorStart)] & 0xFF)
        : 0;

      if (a < b) {
        return -1;
      } else if (a > b) {
        return 1;
      }
    }

    return 0;
  }

  private static void subtractShiftedMultiple(
    byte[] value,
    short valueLength,
    byte[] divisor,
    short divisorOffset,
    short divisorLength,
    short shift,
    short multiple
  ) {
    short carry = 0;
    short index = (short) (valueLength - 1 - shift);
    short divisorIndex = (short) (divisorOffset + divisorLength - 1);

    for (; divisorIndex >= divisorOffset; index--, divisorIndex--) {
      carry += (short) (multiple * (divisor[divisorIndex] & 0xFF));
      short difference = (short) ((value[index] & 0xFF) - (carry & 0xFF));

      value[index] = (byte) difference;
      carry = (short) ((carry >> 8) & 0xFF);

      if (difference < 0) {
        carry++;
      }
    }

    for (; index >= 0 && carry != 0; index--) {
      short difference = (short) ((value[index] & 0xFF) - (carry & 0xFF));

      value[index] = (byte) difference;
      carry = (short) ((carry >> 8) & 0xFF);

      if (difference < 0) {
        carry++;
      }
    }
  }

  private static short leadingZeroBits(short value) {
    for (short count = 0; count < 16; count++) {
      if (value < 0) {
        return count;
      }

      value <<= 1;
    }

    return 16;
  }

  private static short shiftHighDigits(short high, byte middle, byte low, short shift) {
    high <<= shift;

    short mask = (short) (0xFF << (shift >= 8 ? 0 : 8 - shift));
    short bits = (short) (middle & mask & 0xFF);

    if (shift > 8) {
      bits <<= (short) (shift - 8);
    } else {
      bits >>>= (short) (8 - shift);
    }

    high |= bits;

    if (shift > 8) {
      mask = (short) (0xFF << (16 - shift));
      high |= (short) ((low & mask & 0xFF) >> (16 - shift));
    }

    return high;
  }

  /**
   * Adds reduced, equally sized values modulo an immutable modulus. Output may
   * occupy either input window, but must not overlap the modulus.
   */
  public static void modAdd(
    byte[] a,
    short aOffset,
    byte[] b,
    short bOffset,
    byte[] modulus,
    short modulusOffset,
    byte[] out,
    short outOffset,
    short length
  ) {
    short carry = add(a, aOffset, b, bOffset, out, outOffset, length);

    if (carry != 0 || compare(out, outOffset, modulus, modulusOffset, length) >= 0) {
      sub(out, outOffset, modulus, modulusOffset, out, outOffset, length);
    }
  }

  /**
   * Subtracts reduced, equally sized values modulo an immutable modulus. Output
   * may occupy either input window, but must not overlap the modulus.
   */
  public static void modSub(
    byte[] a,
    short aOffset,
    byte[] b,
    short bOffset,
    byte[] modulus,
    short modulusOffset,
    byte[] out,
    short outOffset,
    short length
  ) {
    short borrow = sub(a, aOffset, b, bOffset, out, outOffset, length);

    if (borrow != 0) {
      add(out, outOffset, modulus, modulusOffset, out, outOffset, length);
    }
  }

  /**
   * Multiplies reduced values modulo an odd modulus of at most 32 bytes. Output
   * may occupy either input window. Caller buffers must not overlap the modulus.
   */
  public static void modMult(
    byte[] a,
    short aOffset,
    byte[] b,
    short bOffset,
    byte[] modulus,
    short modulusOffset,
    byte[] out,
    short outOffset,
    short length
  ) {
    byte[] halfSum = sharedTemporaryA;
    byte[] difference = sharedTemporaryB;

    modAdd(a, aOffset, b, bOffset, modulus, modulusOffset, halfSum, (short) 0, length);

    short carry = 0;

    if ((halfSum[(short) (length - 1)] & 1) != 0) {
      carry = add(halfSum, (short) 0, modulus, modulusOffset, halfSum, (short) 0, length);
    }

    shiftRight(halfSum, (short) 0, halfSum, (short) 0, length, (short) 1, (short) (carry << 7));
    modSub(halfSum, (short) 0, b, bOffset, modulus, modulusOffset, difference, (short) 0, length);

    // With h = (a + b) / 2 modulo m, h^2 - (h - b)^2 = a * b modulo m.
    modExp(
      halfSum,
      (short) 0,
      TWO,
      (short) 0,
      (short) TWO.length,
      modulus,
      modulusOffset,
      halfSum,
      (short) 0,
      length
    );
    modExp(
      difference,
      (short) 0,
      TWO,
      (short) 0,
      (short) TWO.length,
      modulus,
      modulusOffset,
      difference,
      (short) 0,
      length
    );
    modSub(
      halfSum,
      (short) 0,
      difference,
      (short) 0,
      modulus,
      modulusOffset,
      out,
      outOffset,
      length
    );
  }

  /**
   * Inverts a nonzero reduced value modulo a prime of at most 32 bytes using
   * a^(p - 2). Output may occupy the input window. Caller buffers must not
   * overlap the modulus.
   */
  public static void modInv(
    byte[] a,
    short aOffset,
    byte[] modulus,
    short modulusOffset,
    byte[] out,
    short outOffset,
    short length
  ) {
    byte[] exponent = sharedExponent;
    short borrow = 2;

    for (short index = (short) (length - 1); index >= 0; index--) {
      short difference = (short) ((modulus[(short) (modulusOffset + index)] & 0xFF) - borrow);

      exponent[index] = (byte) difference;
      borrow = (short) (difference < 0 ? 1 : 0);
    }

    modExp(a, aOffset, exponent, (short) 0, length, modulus, modulusOffset, out, outOffset, length);
  }

  /**
   * Raises a reduced value to a positive exponent using the shared RSA engine.
   * The odd modulus is at most 32 bytes. Output may occupy the input window;
   * output must not overlap the modulus.
   */
  public static void modExp(
    byte[] a,
    short aOffset,
    byte[] exponent,
    short exponentOffset,
    short exponentLength,
    byte[] modulus,
    short modulusOffset,
    byte[] out,
    short outOffset,
    short length
  ) {
    byte[] buffer = sharedExponentiationBuffer;
    short modulusLength = EXPONENT_LENGTH;
    short offset = (short) (modulusLength - length);

    sharedExponentiationKey.setExponent(exponent, exponentOffset, exponentLength);
    Util.arrayFillNonAtomic(buffer, (short) 0, modulusLength, (byte) 0);
    Util.arrayCopyNonAtomic(modulus, modulusOffset, buffer, offset, length);
    sharedExponentiationKey.setModulus(buffer, (short) 0, modulusLength);
    sharedExponentiationCipher.init(sharedExponentiationKey, Cipher.MODE_DECRYPT);

    Util.arrayFillNonAtomic(buffer, (short) 0, modulusLength, (byte) 0);
    Util.arrayCopyNonAtomic(a, aOffset, buffer, offset, length);

    short resultLength = sharedExponentiationCipher.doFinal(
      buffer,
      (short) 0,
      modulusLength,
      buffer,
      (short) 0
    );

    if (resultLength != modulusLength) {
      CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    }

    Util.arrayCopyNonAtomic(buffer, offset, out, outOffset, length);
  }
}
