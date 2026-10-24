package monoidotp;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Random;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LibTOTPTest {

  private static final BigInteger MAX_COUNTER = BigInteger.ONE.shiftLeft(64).subtract(
    BigInteger.ONE
  );

  @Test
  public void unsignedTimeDivisionMatchesBigIntegerAcrossTheEntireEightByteRange() {
    BigInteger[] times = {
      BigInteger.ZERO,
      BigInteger.ONE,
      BigInteger.valueOf(29),
      BigInteger.valueOf(30),
      BigInteger.valueOf(31),
      BigInteger.ONE.shiftLeft(31),
      BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE),
      BigInteger.ONE.shiftLeft(63).subtract(BigInteger.ONE),
      BigInteger.ONE.shiftLeft(63),
      MAX_COUNTER,
    };

    for (BigInteger time : times) {
      for (short period : new short[] { 1, 2, 3, 30, 60, 255, 256, 257, 32767 }) {
        assertCounter(time, period);
      }
    }

    Random random = new Random(6238);

    for (int iteration = 0; iteration < 128; iteration++) {
      assertCounter(new BigInteger(64, random), (short) (1 + random.nextInt(32767)));
    }
  }

  @Test
  public void counterIncrementPropagatesCarriesAndRejectsUnsignedOverflow() {
    for (BigInteger value : new BigInteger[] {
      BigInteger.ZERO,
      BigInteger.valueOf(255),
      BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE),
      BigInteger.ONE.shiftLeft(63).subtract(BigInteger.ONE),
      MAX_COUNTER.subtract(BigInteger.ONE),
    }) {
      byte[] counter = new byte[12];
      Arrays.fill(counter, (byte) 0x55);
      System.arraycopy(unsigned(value), 0, counter, 2, 8);

      LibTOTP.increment(counter, (short) 2);

      Assertions.assertArrayEquals(
        unsigned(value.add(BigInteger.ONE)),
        Arrays.copyOfRange(counter, 2, 10)
      );
      Assertions.assertArrayEquals(new byte[] { 0x55, 0x55 }, Arrays.copyOfRange(counter, 0, 2));
      Assertions.assertArrayEquals(new byte[] { 0x55, 0x55 }, Arrays.copyOfRange(counter, 10, 12));
    }

    byte[] counter = unsigned(MAX_COUNTER.subtract(BigInteger.valueOf(2)));
    LibTOTP.increment(counter, (short) 0);
    LibTOTP.increment(counter, (short) 0);

    Assertions.assertArrayEquals(unsigned(MAX_COUNTER), counter);

    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      LibTOTP.increment(counter, (short) 0)
    );

    Assertions.assertEquals(0x6A80, exception.getReason() & 0xFFFF);
  }

  @Test
  public void dynamicTruncationCoversEveryOffsetSignBitAndLeadingZero() {
    byte[] scratch = new byte[4];

    for (int hashLength : new int[] { 20, 32, 64 }) {
      for (int offset = 0; offset < 16; offset++) {
        for (int value : new int[] { 0, 1, 42, 999999, 1000000, 99999999, 0x7FFFFFFF }) {
          byte[] hash = new byte[hashLength];
          Arrays.fill(hash, (byte) 0xA5);
          ByteBuffer.wrap(hash).putInt(offset, value | 0x80000000);
          hash[hashLength - 1] = (byte) (0xF0 | offset);
          byte[] original = hash.clone();

          for (byte digits : new byte[] { 6, 8 }) {
            byte[] output = new byte[10];
            Arrays.fill(output, (byte) '!');

            LibTOTP.truncate(hash, (short) hashLength, digits, output, scratch);

            int modulus = digits == 6 ? 1000000 : 100000000;
            String expected = String.format(Locale.ROOT, "%0" + digits + "d", value % modulus);

            Assertions.assertEquals(
              expected,
              new String(output, 0, digits, StandardCharsets.US_ASCII)
            );

            for (int index = digits; index < output.length; index++) {
              Assertions.assertEquals('!', output[index]);
            }

            Assertions.assertArrayEquals(original, hash);
          }
        }
      }
    }
  }

  private static void assertCounter(BigInteger seconds, short period) {
    byte[] time = unsigned(seconds);
    byte[] original = time.clone();
    byte[] counter = new byte[12];
    Arrays.fill(counter, (byte) 0x55);

    LibTOTP.counter(time, period, counter, (short) 2);

    Assertions.assertArrayEquals(
      unsigned(seconds.divide(BigInteger.valueOf(period))),
      Arrays.copyOfRange(counter, 2, 10)
    );
    Assertions.assertArrayEquals(original, time);
    Assertions.assertArrayEquals(new byte[] { 0x55, 0x55 }, Arrays.copyOfRange(counter, 0, 2));
    Assertions.assertArrayEquals(new byte[] { 0x55, 0x55 }, Arrays.copyOfRange(counter, 10, 12));
  }

  private static byte[] unsigned(BigInteger value) {
    byte[] encoded = value.toByteArray();
    byte[] result = new byte[8];
    int length = Math.min(result.length, encoded.length);
    System.arraycopy(encoded, encoded.length - length, result, result.length - length, length);

    return result;
  }
}
