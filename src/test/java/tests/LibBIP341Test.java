package tests;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import monoid.CurveSECP256k1;
import monoid.LibBIP340;
import monoid.LibBIP341;
import monoid.LibMath;
import monoid.MonoidException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class LibBIP341Test {

  private CurveSECP256k1 curve;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.bouncycastle.rsa.allow_unsafe_mod", "true");
    MonoidException.init();
    LibMath.init();
    curve = new CurveSECP256k1();
  }

  @AfterEach
  public void dispose() {
    LibMath.dispose();
    MonoidException.dispose();
  }

  @Test
  public void officialKeyPathSpendingVectors() throws Exception {
    List<String[]> vectors = readVectors();

    for (String[] vector : vectors) {
      byte[] key = Hex.decode(vector[1]);
      byte[] publicKey = curve.derivePublicKey(curve.getSharedPrivateKey(key, (short) 0));
      byte[] root = vector[3].isEmpty() ? null : Hex.decode(vector[3]);
      byte[] tweaked = tweak(key, root);
      byte[] outputKey = curve.derivePublicKey(curve.getSharedPrivateKey(tweaked, (short) 0));

      Assertions.assertArrayEquals(Hex.decode(vector[2]), Arrays.copyOfRange(publicKey, 1, 33));
      Assertions.assertArrayEquals(Hex.decode(vector[4]), tweaked, vector[0]);
      Assertions.assertArrayEquals(Hex.decode(vector[5]), Arrays.copyOfRange(outputKey, 1, 33));

      byte[] signature = new byte[64];

      Assertions.assertEquals(
        64,
        LibBIP340.sign(
          curve,
          tweaked,
          (short) 0,
          Hex.decode(vector[6]),
          (short) 0,
          (short) 32,
          new byte[32],
          (short) 0,
          signature,
          (short) 0
        )
      );
      Assertions.assertArrayEquals(Hex.decode(vector[7]), signature, vector[0]);
    }

    Assertions.assertEquals(7, vectors.size());
  }

  @Test
  public void offsetsAndOverlappingOutput() throws Exception {
    String[] vector = readVectors().get(1);

    for (int alias = 0; alias < 3; alias++) {
      byte[] key = new byte[64];
      byte[] root = new byte[64];
      Arrays.fill(key, (byte) 0xA5);
      Arrays.fill(root, (byte) 0xA5);
      System.arraycopy(Hex.decode(vector[1]), 0, key, 3, 32);
      System.arraycopy(Hex.decode(vector[3]), 0, root, 5, 32);
      byte[] originalKey = key.clone();
      byte[] originalRoot = root.clone();
      byte[] output = alias == 1 ? key : alias == 2 ? root : new byte[64];
      byte[] originalOutput = output.clone();

      Assertions.assertEquals(
        32,
        LibBIP341.tweakPrivateKey(curve, key, (short) 3, root, (short) 5, output, (short) 7)
      );
      Assertions.assertArrayEquals(Hex.decode(vector[4]), Arrays.copyOfRange(output, 7, 39));
      Assertions.assertArrayEquals(
        Arrays.copyOfRange(originalOutput, 0, 7),
        Arrays.copyOfRange(output, 0, 7)
      );
      Assertions.assertArrayEquals(
        Arrays.copyOfRange(originalOutput, 39, output.length),
        Arrays.copyOfRange(output, 39, output.length)
      );

      if (alias != 1) {
        Assertions.assertArrayEquals(originalKey, key);
      }

      if (alias != 2) {
        Assertions.assertArrayEquals(originalRoot, root);
      }
    }
  }

  @Test
  public void absentRootAndZeroRootAreDistinctAndParityIsNormalized() throws Exception {
    String[] vector = readVectors().get(0);
    byte[] key = Hex.decode(vector[1]);
    byte[] original = key.clone();
    BigInteger negated = new BigInteger(1, CurveSECP256k1.R).subtract(new BigInteger(1, key));
    byte[] negatedKey = Hex.decode(String.format("%064x", negated));
    byte[] withoutRoot = tweak(key, null);
    byte[] withZeroRoot = tweak(key, new byte[32]);

    Assertions.assertFalse(Arrays.equals(withoutRoot, withZeroRoot));
    Assertions.assertArrayEquals(withoutRoot, tweak(negatedKey, null));
    Assertions.assertArrayEquals(withZeroRoot, tweak(negatedKey, new byte[32]));
    Assertions.assertArrayEquals(original, key);
    Assertions.assertArrayEquals(Hex.decode(vector[4]), tweak(key, null));
  }

  @Test
  public void invalidKeysAndFailedTweakCanBeRetried() throws Exception {
    byte[] output = new byte[32];
    Arrays.fill(output, (byte) 0x55);
    byte[] original = output.clone();

    for (byte[] key : new byte[][] { new byte[32], CurveSECP256k1.R.clone() }) {
      Assertions.assertThrows(MonoidException.class, () ->
        LibBIP341.tweakPrivateKey(curve, key, (short) 0, null, (short) 0, output, (short) 0)
      );
      Assertions.assertArrayEquals(original, output);
    }

    String[] vector = readVectors().get(1);
    byte[] key = Hex.decode(vector[1]);
    byte[] root = Hex.decode(vector[3]);

    Assertions.assertThrows(RuntimeException.class, () ->
      LibBIP341.tweakPrivateKey(curve, key, (short) 0, root, (short) 0, new byte[31], (short) 0)
    );
    Assertions.assertArrayEquals(Hex.decode(vector[4]), tweak(key, root));
  }

  private byte[] tweak(byte[] key, byte[] root) {
    byte[] output = new byte[32];

    Assertions.assertEquals(
      32,
      LibBIP341.tweakPrivateKey(curve, key, (short) 0, root, (short) 0, output, (short) 0)
    );

    return output;
  }

  private static List<String[]> readVectors() throws Exception {
    List<String[]> vectors = new ArrayList<>();

    try (
      BufferedReader reader = new BufferedReader(
        new InputStreamReader(
          LibBIP341Test.class.getResourceAsStream("/bip341.tsv"),
          StandardCharsets.US_ASCII
        )
      );
    ) {
      for (String line; (line = reader.readLine()) != null; ) {
        if (!line.startsWith("#")) {
          vectors.add(line.split("\t", -1));
        }
      }
    }

    return vectors;
  }
}
