package monoidsecuritykey;

import com.licel.jcardsim.smartcardio.CardSimulator;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LibCOSETest {

  @Test
  public void copiesOnlyTheSignaturePrefixBeforeScratchIsReused() {
    new CardSimulator();
    byte[] scratch = new byte[260];
    Arrays.fill(scratch, 64, scratch.length, (byte) 0x5A);
    scratch[31] = 1;
    scratch[63] = (byte) 0x80;

    byte[] encoded = LibCOSE.signatureDER(scratch);
    Arrays.fill(scratch, (byte) 0xA5);

    Assertions.assertArrayEquals(new byte[] { 0x30, 7, 2, 1, 1, 2, 2, 0, (byte) 0x80 }, encoded);
  }

  @Test
  public void encodesMinimalPositiveIntegersAtEveryP256MagnitudeLength() {
    new CardSimulator();
    List<byte[]> values = new ArrayList<>();
    values.add(new byte[32]);
    for (int length = 1; length <= 32; length++) {
      for (int first : new int[] { 1, 0x7F, 0x80, 0xFF }) {
        byte[] value = new byte[32];
        Arrays.fill(value, 32 - length, 32, (byte) 0x45);
        value[32 - length] = (byte) first;
        values.add(value);
      }
    }

    for (byte[] r : values) {
      for (byte[] s : values) {
        byte[] signature = new byte[64];
        System.arraycopy(r, 0, signature, 0, 32);
        System.arraycopy(s, 0, signature, 32, 32);
        byte[] original = signature.clone();
        // BigInteger supplies the independent minimal signed-positive representation.
        byte[] rInteger = new BigInteger(1, r).toByteArray();
        byte[] sInteger = new BigInteger(1, s).toByteArray();
        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        expected.write(0x30);
        expected.write(4 + rInteger.length + sInteger.length);
        expected.write(2);
        expected.write(rInteger.length);
        expected.write(rInteger, 0, rInteger.length);
        expected.write(2);
        expected.write(sInteger.length);
        expected.write(sInteger, 0, sInteger.length);

        Assertions.assertArrayEquals(expected.toByteArray(), LibCOSE.signatureDER(signature));
        byte[] destination = new byte[80];
        Arrays.fill(destination, (byte) 0x5A);
        short length = LibCOSE.signatureDER(signature, destination, (short) 3);
        Assertions.assertEquals(expected.size(), length);
        Assertions.assertArrayEquals(
          expected.toByteArray(),
          Arrays.copyOfRange(destination, 3, 3 + length)
        );
        Assertions.assertArrayEquals(
          new byte[] { 0x5A, 0x5A, 0x5A },
          Arrays.copyOf(destination, 3)
        );
        for (int index = 3 + length; index < destination.length; index++) {
          Assertions.assertEquals((byte) 0x5A, destination[index]);
        }
        Assertions.assertArrayEquals(original, signature);
      }
    }
  }
}
