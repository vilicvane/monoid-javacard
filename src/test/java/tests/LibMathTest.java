package tests;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import javacard.framework.JCSystem;
import monoid.LibMath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class LibMathTest {

  private static final BigInteger FIELD = BigInteger.ONE.shiftLeft(255).subtract(
    BigInteger.valueOf(19)
  );
  private static final BigInteger ORDER = BigInteger.ONE.shiftLeft(252).add(
    new BigInteger("27742317777372353535851937790883648493")
  );

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.bouncycastle.rsa.allow_unsafe_mod", "true");
    LibMath.init();
  }

  @AfterEach
  public void dispose() throws IllegalAccessException {
    try {
      assertScratchCleared();
    } finally {
      LibMath.dispose();
    }
  }

  @Test
  public void rightShiftMatchesUnsignedArithmeticWithCarryAndInPlaceOutput() {
    byte[] input = new byte[34];

    for (int index = 0; index < input.length; index++) {
      input[index] = (byte) (index * 73 + 128);
    }

    BigInteger value = new BigInteger(1, Arrays.copyOfRange(input, 1, 33));

    for (short bits = 0; bits < 8; bits++) {
      for (short prefix = 0; prefix < (1 << bits); prefix++) {
        short carry = (short) (byte) (prefix << (8 - bits));
        BigInteger expected = BigInteger.valueOf(prefix).shiftLeft(256).add(value).shiftRight(bits);

        for (boolean inPlace : new boolean[] { false, true }) {
          byte[] source = input.clone();
          byte[] out = inPlace ? source : new byte[36];
          short outOffset = (short) (inPlace ? 1 : 2);
          byte[] before = out.clone();

          LibMath.shiftRight(source, (short) 1, out, outOffset, (short) 32, bits, carry);

          Assertions.assertEquals(
            expected,
            new BigInteger(1, Arrays.copyOfRange(out, outOffset, outOffset + 32))
          );
          System.arraycopy(before, outOffset, out, outOffset, 32);
          Assertions.assertArrayEquals(before, out);

          if (!inPlace) {
            Assertions.assertArrayEquals(input, source);
          }
        }
      }
    }
  }

  @Test
  public void unsignedArithmeticMatchesBigIntegerWithCarryBorrowAndAliasedOutput() {
    Random random = new Random(0x25519);

    for (short length : new short[] { 1, 2, 32, 64 }) {
      BigInteger limit = BigInteger.ONE.shiftLeft(length * 8);
      BigInteger[] boundaries = {
        BigInteger.ZERO,
        BigInteger.ONE,
        BigInteger.valueOf(127),
        BigInteger.valueOf(128),
        limit.shiftRight(1),
        limit.subtract(BigInteger.ONE),
      };

      for (BigInteger a : boundaries) {
        for (BigInteger b : boundaries) {
          checkArithmetic(a, b, length);
        }
      }

      for (int index = 0; index < 64; index++) {
        checkArithmetic(
          new BigInteger(length * 8, random),
          new BigInteger(length * 8, random),
          length
        );
      }
    }
  }

  @Test
  public void reductionMatchesBigIntegerForWideInputsAndModulusBoundaries() {
    Random random = new Random(0x51225519);

    for (BigInteger modulus : new BigInteger[] { FIELD, ORDER }) {
      for (short inputLength : new short[] { 32, 64 }) {
        BigInteger[] boundaries = {
          BigInteger.ZERO,
          BigInteger.ONE,
          modulus.subtract(BigInteger.ONE),
          modulus,
          modulus.add(BigInteger.ONE),
          modulus.shiftLeft(1),
          BigInteger.ONE.shiftLeft(inputLength * 8).subtract(BigInteger.ONE),
        };

        for (BigInteger value : boundaries) {
          checkReduction(value, inputLength, modulus, (short) 32);
        }

        for (int index = 0; index < 64; index++) {
          checkReduction(new BigInteger(inputLength * 8, random), inputLength, modulus, (short) 32);
        }
      }
    }

    // Exercise overflow during reduction and leading-zero modulus bytes as well.
    for (BigInteger modulus : new BigInteger[] {
      BigInteger.ONE,
      BigInteger.valueOf(2),
      BigInteger.valueOf(128),
      BigInteger.valueOf(255),
      BigInteger.valueOf(256),
      BigInteger.valueOf(65521),
    }) {
      for (int index = 0; index < 32; index++) {
        checkReduction(new BigInteger(512, random), (short) 64, modulus, (short) 2);
      }
    }
  }

  @Test
  public void reductionMatchesBigIntegerAcrossEveryInputAndModulusWidth() {
    Random random = new Random(0xdec25519);

    for (short length = 1; length <= 32; length++) {
      BigInteger limit = BigInteger.ONE.shiftLeft(length * 8);
      BigInteger[] moduli = {
        BigInteger.ONE,
        limit.shiftRight(1),
        limit.subtract(BigInteger.ONE),
        new BigInteger(length * 8, random).setBit(0),
        new BigInteger(1 + random.nextInt(length * 8), random).setBit(0),
      };

      for (short inputLength = 0; inputLength <= 64; inputLength++) {
        for (BigInteger modulus : moduli) {
          checkReduction(
            BigInteger.ONE.shiftLeft(inputLength * 8).subtract(BigInteger.ONE),
            inputLength,
            modulus,
            length
          );
          checkReduction(new BigInteger(inputLength * 8, random), inputLength, modulus, length);
        }
      }
    }
  }

  @Test
  public void reductionHandlesLeadingZerosAndLargeQuotientDigits() {
    Random random = new Random(0x7ff25519);

    for (short length = 1; length <= 32; length++) {
      for (int highByte : new int[] { 1, 127, 128, 255 }) {
        BigInteger modulus = new BigInteger((length - 1) * 8, random).or(
          BigInteger.valueOf(highByte).shiftLeft((length - 1) * 8)
        );

        for (int quotient : new int[] { 1, 127, 128, 255, 256, 65535, 0xFFFFFF }) {
          for (BigInteger remainder : new BigInteger[] {
            BigInteger.ZERO,
            modulus.shiftRight(1),
            modulus.subtract(BigInteger.ONE),
          }) {
            BigInteger value = modulus.multiply(BigInteger.valueOf(quotient)).add(remainder);
            short inputLength = (short) ((value.bitLength() + 7) / 8);

            checkReduction(value, inputLength, modulus, length);
            checkReduction(value, (short) 64, modulus, (short) 32);
          }
        }
      }
    }
  }

  @Test
  public void modularAdditionAndSubtractionMatchBigIntegerWithAliasedOutput() {
    Random random = new Random(0xadd25519);

    for (BigInteger modulus : new BigInteger[] {
      FIELD,
      ORDER,
      BigInteger.ONE.shiftLeft(256).subtract(BigInteger.valueOf(189)),
    }) {
      BigInteger[] boundaries = {
        BigInteger.ZERO,
        BigInteger.ONE,
        modulus.shiftRight(1),
        modulus.subtract(BigInteger.ONE),
      };

      for (BigInteger a : boundaries) {
        for (BigInteger b : boundaries) {
          checkModularArithmetic(a, b, modulus, false);
        }
      }

      for (int index = 0; index < 64; index++) {
        checkModularArithmetic(
          new BigInteger(256, random).mod(modulus),
          new BigInteger(256, random).mod(modulus),
          modulus,
          false
        );
      }
    }
  }

  @Test
  public void modularMultiplicationMatchesBigIntegerWithAliasedOutput() {
    Random random = new Random(0xbed25519);

    for (BigInteger modulus : new BigInteger[] {
      FIELD,
      ORDER,
      BigInteger.ONE.shiftLeft(256).subtract(BigInteger.valueOf(189)),
    }) {
      BigInteger[] boundaries = {
        BigInteger.ZERO,
        BigInteger.ONE,
        BigInteger.valueOf(2),
        modulus.shiftRight(1),
        modulus.subtract(BigInteger.valueOf(2)),
        modulus.subtract(BigInteger.ONE),
      };

      for (BigInteger a : boundaries) {
        for (BigInteger b : boundaries) {
          checkModularArithmetic(a, b, modulus, true);
        }
      }

      for (int index = 0; index < 32; index++) {
        checkModularArithmetic(
          new BigInteger(256, random).mod(modulus),
          new BigInteger(256, random).mod(modulus),
          modulus,
          true
        );
      }
    }
  }

  @Test
  public void modularInverseAndExponentiationReuseTheEngineAcrossModuliAndExponentLengths() {
    Random random = new Random(0x1ed25519);

    for (int index = 0; index < 24; index++) {
      BigInteger modulus = index % 2 == 0 ? FIELD : ORDER;
      BigInteger value;

      if (index < 2) {
        value = BigInteger.ONE;
      } else if (index < 4) {
        value = modulus.subtract(BigInteger.ONE);
      } else {
        value = new BigInteger(256, random)
          .mod(modulus.subtract(BigInteger.ONE))
          .add(BigInteger.ONE);
      }

      for (boolean inPlace : new boolean[] { false, true }) {
        byte[] input = padded(value, 32, 2);
        byte[] inputBefore = input.clone();
        byte[] mod = padded(modulus, 32, 3);
        byte[] modBefore = mod.clone();
        byte[] out = inPlace ? input : padded(BigInteger.ZERO, 32, 5);
        short outOffset = (short) (inPlace ? 2 : 5);
        byte[] outBefore = out.clone();

        LibMath.modInv(input, (short) 2, mod, (short) 3, out, outOffset, (short) 32);

        assertValue(value.modInverse(modulus), out, outOffset, 32);
        assertOutsideUnchanged(outBefore, out, outOffset, 32);
        Assertions.assertArrayEquals(modBefore, mod);

        if (!inPlace) {
          Assertions.assertArrayEquals(inputBefore, input);
        }
      }

      for (BigInteger exponent : new BigInteger[] {
        BigInteger.valueOf(2),
        modulus.subtract(BigInteger.valueOf(2)),
        BigInteger.ONE,
      }) {
        byte[] input = padded(value, 32, 2);
        byte[] inputBefore = input.clone();
        byte[] mod = padded(modulus, 32, 3);
        byte[] modBefore = mod.clone();
        short exponentLength = (short) ((exponent.bitLength() + 7) / 8);
        byte[] exp = padded(exponent, exponentLength, 4);
        byte[] expBefore = exp.clone();

        LibMath.modExp(
          input,
          (short) 2,
          exp,
          (short) 4,
          exponentLength,
          mod,
          (short) 3,
          input,
          (short) 2,
          (short) 32
        );

        assertValue(value.modPow(exponent, modulus), input, 2, 32);
        assertOutsideUnchanged(inputBefore, input, 2, 32);
        Assertions.assertArrayEquals(modBefore, mod);
        Assertions.assertArrayEquals(expBefore, exp);
      }
    }
  }

  @Test
  public void failedModularOperationsClearSharedScratchAndCanBeRetried() throws Exception {
    byte[] input = padded(BigInteger.valueOf(42), 32, 0);
    byte[] modulus = padded(FIELD, 32, 0);
    byte[] shortOutput = new byte[31];
    byte[] exponent = { 3 };
    short offset = 0;
    short length = 32;

    Assertions.assertThrows(RuntimeException.class, () ->
      LibMath.mod(input, offset, length, modulus, offset, length, shortOutput, offset)
    );
    assertScratchCleared();

    Assertions.assertThrows(RuntimeException.class, () ->
      LibMath.modMult(input, offset, input, offset, modulus, offset, shortOutput, offset, length)
    );
    assertScratchCleared();

    Assertions.assertThrows(RuntimeException.class, () ->
      LibMath.modInv(input, offset, modulus, offset, shortOutput, offset, length)
    );
    assertScratchCleared();

    Assertions.assertThrows(RuntimeException.class, () ->
      LibMath.modExp(
        input,
        offset,
        exponent,
        offset,
        (short) 1,
        modulus,
        offset,
        shortOutput,
        offset,
        length
      )
    );
    assertScratchCleared();

    byte[] output = new byte[32];

    LibMath.modMult(input, offset, input, offset, modulus, offset, output, offset, length);
    assertValue(BigInteger.valueOf(42).pow(2), output, 0, 32);
    assertScratchCleared();
    LibMath.modInv(input, offset, modulus, offset, output, offset, length);
    assertValue(BigInteger.valueOf(42).modInverse(FIELD), output, 0, 32);
    assertScratchCleared();
  }

  private static void assertScratchCleared() throws IllegalAccessException {
    for (Field field : LibMath.class.getDeclaredFields()) {
      if (field.getType() != byte[].class || !Modifier.isStatic(field.getModifiers())) {
        continue;
      }

      field.setAccessible(true);
      byte[] buffer = (byte[]) field.get(null);

      if (JCSystem.isTransient(buffer) != JCSystem.NOT_A_TRANSIENT_OBJECT) {
        Assertions.assertArrayEquals(new byte[buffer.length], buffer, field.getName());
      }
    }
  }

  private static void checkArithmetic(BigInteger aValue, BigInteger bValue, short length) {
    BigInteger limit = BigInteger.ONE.shiftLeft(length * 8);

    for (boolean subtract : new boolean[] { false, true }) {
      for (int alias = 0; alias < 3; alias++) {
        byte[] a = padded(aValue, length, 2);
        byte[] b = padded(bValue, length, 4);
        byte[] aBefore = a.clone();
        byte[] bBefore = b.clone();
        byte[] out = alias == 1 ? a : alias == 2 ? b : padded(BigInteger.ZERO, length, 6);
        short outOffset = (short) (alias == 1 ? 2 : alias == 2 ? 4 : 6);
        byte[] outBefore = out.clone();

        Assertions.assertEquals(
          aValue.compareTo(bValue),
          LibMath.compare(a, (short) 2, b, (short) 4, length)
        );
        short carry = subtract
          ? LibMath.sub(a, (short) 2, b, (short) 4, out, outOffset, length)
          : LibMath.add(a, (short) 2, b, (short) 4, out, outOffset, length);
        BigInteger expected = subtract ? aValue.subtract(bValue) : aValue.add(bValue);

        Assertions.assertEquals(
          subtract ? (expected.signum() < 0 ? 1 : 0) : expected.divide(limit).intValue(),
          carry
        );
        assertValue(expected.mod(limit), out, outOffset, length);
        assertOutsideUnchanged(outBefore, out, outOffset, length);

        if (alias != 1) {
          Assertions.assertArrayEquals(aBefore, a);
        }

        if (alias != 2) {
          Assertions.assertArrayEquals(bBefore, b);
        }
      }
    }
  }

  private static void checkReduction(
    BigInteger value,
    short inputLength,
    BigInteger modulus,
    short length
  ) {
    // Exact alias and overlap on either side are supported: reduction consumes
    // the entire input before publishing the fixed-width remainder.
    for (int alias = 0; alias < 4; alias++) {
      byte[] input = Arrays.copyOf(
        padded(value, inputLength, 2),
        8 + Math.max(inputLength, length)
      );
      byte[] inputBefore = input.clone();
      byte[] mod = padded(modulus, length, 3);
      byte[] modBefore = mod.clone();
      byte[] out = alias == 0 ? padded(BigInteger.ZERO, length, 6) : input;
      short outOffset = (short) (alias == 0 ? 6 : alias == 1 ? 2 : alias == 2 ? 1 : 5);
      byte[] outBefore = out.clone();

      LibMath.mod(input, (short) 2, inputLength, mod, (short) 3, length, out, outOffset);

      assertValue(value.mod(modulus), out, outOffset, length);
      assertOutsideUnchanged(outBefore, out, outOffset, length);
      Assertions.assertArrayEquals(modBefore, mod);

      if (alias == 0) {
        Assertions.assertArrayEquals(inputBefore, input);
      }
    }
  }

  private static void checkModularArithmetic(
    BigInteger aValue,
    BigInteger bValue,
    BigInteger modulus,
    boolean multiply
  ) {
    for (int operation = multiply ? 2 : 0; operation < (multiply ? 3 : 2); operation++) {
      for (int alias = 0; alias < 3; alias++) {
        byte[] a = padded(aValue, 32, 2);
        byte[] b = padded(bValue, 32, 4);
        byte[] aBefore = a.clone();
        byte[] bBefore = b.clone();
        byte[] mod = padded(modulus, 32, 3);
        byte[] modBefore = mod.clone();
        byte[] out = alias == 1 ? a : alias == 2 ? b : padded(BigInteger.ZERO, 32, 6);
        short outOffset = (short) (alias == 1 ? 2 : alias == 2 ? 4 : 6);
        byte[] outBefore = out.clone();
        BigInteger expected;

        if (operation == 0) {
          LibMath.modAdd(a, (short) 2, b, (short) 4, mod, (short) 3, out, outOffset, (short) 32);
          expected = aValue.add(bValue);
        } else if (operation == 1) {
          LibMath.modSub(a, (short) 2, b, (short) 4, mod, (short) 3, out, outOffset, (short) 32);
          expected = aValue.subtract(bValue);
        } else {
          LibMath.modMult(a, (short) 2, b, (short) 4, mod, (short) 3, out, outOffset, (short) 32);
          expected = aValue.multiply(bValue);
        }

        assertValue(expected.mod(modulus), out, outOffset, 32);
        assertOutsideUnchanged(outBefore, out, outOffset, 32);
        Assertions.assertArrayEquals(modBefore, mod);

        if (alias != 1) {
          Assertions.assertArrayEquals(aBefore, a);
        }

        if (alias != 2) {
          Assertions.assertArrayEquals(bBefore, b);
        }
      }
    }
  }

  private static byte[] padded(BigInteger value, int length, int offset) {
    byte[] bytes = value.toByteArray();
    byte[] out = new byte[offset + length + 3];
    Arrays.fill(out, (byte) 0xA5);
    Arrays.fill(out, offset, offset + length, (byte) 0);
    int copyLength = Math.min(bytes.length, length);
    System.arraycopy(
      bytes,
      bytes.length - copyLength,
      out,
      offset + length - copyLength,
      copyLength
    );

    return out;
  }

  private static void assertValue(BigInteger expected, byte[] actual, int offset, int length) {
    Assertions.assertEquals(
      expected,
      new BigInteger(1, Arrays.copyOfRange(actual, offset, offset + length))
    );
  }

  private static void assertOutsideUnchanged(byte[] before, byte[] after, int offset, int length) {
    Assertions.assertArrayEquals(
      Arrays.copyOfRange(before, 0, offset),
      Arrays.copyOfRange(after, 0, offset)
    );
    Assertions.assertArrayEquals(
      Arrays.copyOfRange(before, offset + length, before.length),
      Arrays.copyOfRange(after, offset + length, after.length)
    );
  }
}
