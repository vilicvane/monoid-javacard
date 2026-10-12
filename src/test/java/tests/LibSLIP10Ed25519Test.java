package tests;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import monoid.LibHMACSha512;
import monoid.LibSLIP10Ed25519;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class LibSLIP10Ed25519Test {

  @BeforeEach
  public void initialize() {
    LibHMACSha512.init();
  }

  @AfterEach
  public void dispose() {
    LibHMACSha512.dispose();
  }

  @Test
  public void officialVectors() throws Exception {
    LibSLIP10Ed25519 deriver = new LibSLIP10Ed25519();
    byte[] output = new byte[64];
    short count = 0;

    try (
      BufferedReader reader = new BufferedReader(
        new InputStreamReader(
          getClass().getResourceAsStream("/slip10-ed25519.tsv"),
          StandardCharsets.US_ASCII
        )
      );
    ) {
      for (String line; (line = reader.readLine()) != null; ) {
        if (line.startsWith("#")) {
          continue;
        }

        String[] fields = line.split("\t", -1);
        byte[] master = deriveMaster(Hex.decode(fields[0]));
        byte[] path = Hex.decode(fields[1]);
        short length = deriver.derive(
          master,
          (short) 0,
          (short) master.length,
          path,
          (short) 0,
          (short) path.length,
          output,
          (short) 0
        );

        Assertions.assertEquals(64, length);
        Assertions.assertArrayEquals(Hex.decode(fields[2] + fields[3]), output);
        count++;
      }
    }

    Assertions.assertEquals(12, count);
  }

  @Test
  public void offsetsAndOverlappingOutput() {
    LibSLIP10Ed25519 deriver = new LibSLIP10Ed25519();
    byte[] buffer = new byte[90];
    byte[] master = deriveMaster(Hex.decode("000102030405060708090a0b0c0d0e0f"));
    byte[] path = Hex.decode("8000000080000001");
    System.arraycopy(master, 0, buffer, 3, master.length);
    System.arraycopy(path, 0, buffer, 70, path.length);

    deriver.derive(
      buffer,
      (short) 3,
      (short) 64,
      buffer,
      (short) 70,
      (short) 8,
      buffer,
      (short) 16
    );

    Assertions.assertArrayEquals(
      Hex.decode(
        "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2" +
        "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"
      ),
      Arrays.copyOfRange(buffer, 16, 80)
    );
  }

  @Test
  public void rejectsInvalidInputsWithoutPublishingPartialKey() {
    LibSLIP10Ed25519 deriver = new LibSLIP10Ed25519();
    byte[] master = deriveMaster(Hex.decode("000102030405060708090a0b0c0d0e0f"));
    byte[] output = new byte[64];
    Arrays.fill(output, (byte) 0x55);
    byte[] original = output.clone();

    for (byte[] path : new byte[][] {
      Hex.decode("00000000"),
      Hex.decode("8000000000000001"),
      Hex.decode("800000"),
    }) {
      ISOException exception = Assertions.assertThrows(ISOException.class, () ->
        deriver.derive(
          master,
          (short) 0,
          (short) master.length,
          path,
          (short) 0,
          (short) path.length,
          output,
          (short) 0
        )
      );

      Assertions.assertEquals(
        path.length % 4 == 0 ? ISO7816.SW_WRONG_DATA : ISO7816.SW_WRONG_LENGTH,
        exception.getReason()
      );
      Assertions.assertArrayEquals(original, output);
    }

    for (short length : new short[] { -1, 0, 32, 63, 65 }) {
      Assertions.assertThrows(ISOException.class, () ->
        deriver.derive(
          new byte[65],
          (short) 0,
          length,
          new byte[0],
          (short) 0,
          (short) 0,
          output,
          (short) 0
        )
      );
      Assertions.assertArrayEquals(original, output);
    }

    deriver.derive(
      master,
      (short) 0,
      (short) master.length,
      new byte[0],
      (short) 0,
      (short) 0,
      output,
      (short) 0
    );
    Assertions.assertArrayEquals(
      Hex.decode(
        "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7" +
        "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
      ),
      output
    );
  }

  private static byte[] deriveMaster(byte[] seed) {
    return LibHMACSha512.digest("ed25519 seed".getBytes(StandardCharsets.US_ASCII), seed);
  }
}
