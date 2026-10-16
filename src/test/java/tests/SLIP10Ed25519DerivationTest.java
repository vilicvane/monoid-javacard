package tests;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import monoid.KeyDerivation;
import monoid.LibHMACSha512;
import monoid.SLIP10Ed25519Derivation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SLIP10Ed25519DerivationTest {

  private SLIP10Ed25519Derivation derivation;

  @BeforeEach
  public void initialize() {
    LibHMACSha512.init();
    KeyDerivation.init();
    derivation = new SLIP10Ed25519Derivation();
  }

  @AfterEach
  public void dispose() {
    KeyDerivation.dispose();
    LibHMACSha512.dispose();
  }

  @Test
  public void officialVectors() throws Exception {
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
        byte[] output = derivation.derive(master, path);

        Assertions.assertEquals(64, output.length);
        Assertions.assertArrayEquals(Hex.decode(fields[2] + fields[3]), output);
        count++;
      }
    }

    Assertions.assertEquals(12, count);
  }

  @Test
  public void preservesInputsAndReturnsIndependentOutput() {
    byte[] master = deriveMaster(Hex.decode("000102030405060708090a0b0c0d0e0f"));
    byte[] path = Hex.decode("8000000080000001");
    byte[] originalMaster = master.clone();
    byte[] originalPath = path.clone();
    byte[] output = derivation.derive(master, path);

    Assertions.assertArrayEquals(
      Hex.decode(
        "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2" +
        "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"
      ),
      output
    );
    Assertions.assertArrayEquals(originalMaster, master);
    Assertions.assertArrayEquals(originalPath, path);
    Assertions.assertNotSame(master, output);
    Assertions.assertNotSame(path, output);

    byte[] repeated = derivation.derive(master, path);
    Assertions.assertArrayEquals(output, repeated);
    Assertions.assertNotSame(output, repeated);
  }

  @Test
  public void rejectsInvalidInputsWithoutChangingInputs() {
    byte[] master = deriveMaster(Hex.decode("000102030405060708090a0b0c0d0e0f"));
    byte[] originalMaster = master.clone();

    for (byte[] path : new byte[][] {
      Hex.decode("00000000"),
      Hex.decode("8000000000000001"),
      Hex.decode("800000"),
    }) {
      byte[] originalPath = path.clone();
      ISOException exception = Assertions.assertThrows(ISOException.class, () ->
        derivation.derive(master, path)
      );

      Assertions.assertEquals(
        path.length % 4 == 0 ? ISO7816.SW_WRONG_DATA : ISO7816.SW_WRONG_LENGTH,
        exception.getReason()
      );
      Assertions.assertArrayEquals(originalMaster, master);
      Assertions.assertArrayEquals(originalPath, path);
    }

    for (short length : new short[] { 0, 32, 63, 65 }) {
      byte[] invalidMaster = new byte[length];
      byte[] original = invalidMaster.clone();
      ISOException exception = Assertions.assertThrows(ISOException.class, () ->
        derivation.derive(invalidMaster, new byte[0])
      );

      Assertions.assertEquals(ISO7816.SW_WRONG_LENGTH, exception.getReason());
      Assertions.assertArrayEquals(original, invalidMaster);
    }

    byte[] output = derivation.derive(master, new byte[0]);
    Assertions.assertArrayEquals(
      Hex.decode(
        "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7" +
        "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
      ),
      output
    );
    Assertions.assertNotSame(master, output);
  }

  private static byte[] deriveMaster(byte[] seed) {
    return LibHMACSha512.digest("ed25519 seed".getBytes(StandardCharsets.US_ASCII), seed);
  }
}
