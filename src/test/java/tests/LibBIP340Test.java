package tests;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.bouncycastle.math.ec.ECPoint;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import monoid.CurveSECP256k1;
import monoid.LibBIP340;
import monoid.LibMath;
import monoid.MonoidException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class LibBIP340Test {

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
  public void officialVectorsAndSharedCurveReuse() throws Exception {
    List<String[]> vectors = readVectors();

    for (int pass = 0; pass < 2; pass++) {
      for (String[] vector : vectors) {
        byte[] key = Hex.decode(vector[1]);
        byte[] publicKey = curve.derivePublicKey(curve.getSharedPrivateKey(key, (short) 0));
        byte[] aux = Hex.decode(vector[3]);
        byte[] message = Hex.decode(vector[4]);
        byte[] signature = sign(key, message, aux);

        Assertions.assertArrayEquals(
          Hex.decode(vector[2]),
          Arrays.copyOfRange(publicKey, 1, 33),
          vector[0]
        );
        Assertions.assertArrayEquals(Hex.decode(vector[5]), signature, vector[0]);
        assertSignature(Hex.decode(vector[2]), message, signature);
      }
    }

    Assertions.assertEquals(8, vectors.size());
  }

  @Test
  public void offsetsAndOverlappingOutput() throws Exception {
    String[] vector = readVectors().get(1);

    for (int alias = 0; alias < 4; alias++) {
      byte[] key = padded(Hex.decode(vector[1]), 3);
      byte[] aux = padded(Hex.decode(vector[3]), 5);
      byte[] message = padded(Hex.decode(vector[4]), 7);
      byte[] originalKey = key.clone();
      byte[] originalAux = aux.clone();
      byte[] originalMessage = message.clone();
      byte[] output = alias == 1 ? key : alias == 2 ? aux : alias == 3 ? message : new byte[96];
      byte[] originalOutput = output.clone();

      Assertions.assertEquals(
        64,
        LibBIP340.sign(
          curve,
          key,
          (short) 3,
          message,
          (short) 7,
          (short) 32,
          aux,
          (short) 5,
          output,
          (short) 2
        )
      );
      Assertions.assertArrayEquals(Hex.decode(vector[5]), Arrays.copyOfRange(output, 2, 66));
      Assertions.assertArrayEquals(
        Arrays.copyOfRange(originalOutput, 0, 2),
        Arrays.copyOfRange(output, 0, 2)
      );
      Assertions.assertArrayEquals(
        Arrays.copyOfRange(originalOutput, 66, output.length),
        Arrays.copyOfRange(output, 66, output.length)
      );

      if (alias != 1) {
        Assertions.assertArrayEquals(originalKey, key);
      }

      if (alias != 2) {
        Assertions.assertArrayEquals(originalAux, aux);
      }

      if (alias != 3) {
        Assertions.assertArrayEquals(originalMessage, message);
      }
    }
  }

  @Test
  public void auxiliaryRandomnessAndNegatedPrivateKeys() throws Exception {
    String[] vector = readVectors().get(0);
    byte[] key = Hex.decode(vector[1]);
    BigInteger negated = new BigInteger(1, CurveSECP256k1.R).subtract(new BigInteger(1, key));
    byte[] negatedKey = Hex.decode(String.format("%064x", negated));
    byte[] message = Hex.decode(vector[4]);
    byte[] aux = new byte[32];
    byte[] first = sign(key, message, aux);

    Assertions.assertArrayEquals(first, sign(negatedKey, message, aux));
    aux[31] = 1;

    byte[] second = sign(key, message, aux);

    Assertions.assertFalse(Arrays.equals(first, second));
    Assertions.assertArrayEquals(second, sign(negatedKey, message, aux));
    assertSignature(Hex.decode(vector[2]), message, second);
    Assertions.assertArrayEquals(Hex.decode(vector[5]), sign(key, message, new byte[32]));
  }

  @Test
  public void invalidKeysAndFailedSignatureCanBeRetried() throws Exception {
    byte[] output = new byte[64];
    Arrays.fill(output, (byte) 0x55);
    byte[] original = output.clone();

    for (byte[] key : new byte[][] { new byte[32], CurveSECP256k1.R.clone() }) {
      Assertions.assertThrows(MonoidException.class, () ->
        LibBIP340.sign(
          curve,
          key,
          (short) 0,
          new byte[32],
          (short) 0,
          (short) 32,
          new byte[32],
          (short) 0,
          output,
          (short) 0
        )
      );
      Assertions.assertArrayEquals(original, output);
    }

    String[] vector = readVectors().get(1);
    byte[] key = Hex.decode(vector[1]);
    byte[] aux = Hex.decode(vector[3]);
    byte[] message = Hex.decode(vector[4]);

    Assertions.assertThrows(RuntimeException.class, () ->
      LibBIP340.sign(
        curve,
        key,
        (short) 0,
        message,
        (short) 0,
        (short) message.length,
        aux,
        (short) 0,
        new byte[63],
        (short) 0
      )
    );
    Assertions.assertArrayEquals(Hex.decode(vector[5]), sign(key, message, aux));
  }

  private byte[] sign(byte[] key, byte[] message, byte[] aux) {
    byte[] signature = new byte[64];

    Assertions.assertEquals(
      64,
      LibBIP340.sign(
        curve,
        key,
        (short) 0,
        message,
        (short) 0,
        (short) message.length,
        aux,
        (short) 0,
        signature,
        (short) 0
      )
    );

    return signature;
  }

  private static void assertSignature(byte[] publicKey, byte[] message, byte[] signature)
    throws Exception {
    // Independent host verification uses point arithmetic, not the card's scalar helpers.
    X9ECParameters parameters = SECNamedCurves.getByName("secp256k1");
    byte[] compressed = new byte[33];
    compressed[0] = 2;
    System.arraycopy(publicKey, 0, compressed, 1, 32);
    ECPoint point = parameters.getCurve().decodePoint(compressed);
    MessageDigest hash = MessageDigest.getInstance("SHA-256");
    byte[] tag = hash.digest("BIP0340/challenge".getBytes(StandardCharsets.US_ASCII));
    hash.update(tag);
    hash.update(tag);
    hash.update(signature, 0, 32);
    hash.update(publicKey);
    BigInteger challenge = new BigInteger(1, hash.digest(message)).mod(parameters.getN());
    BigInteger response = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));

    Assertions.assertTrue(response.compareTo(parameters.getN()) < 0);

    ECPoint nonce = parameters.getG().multiply(response).subtract(point.multiply(challenge));
    nonce = nonce.normalize();

    Assertions.assertFalse(nonce.isInfinity());
    Assertions.assertFalse(nonce.getAffineYCoord().toBigInteger().testBit(0));
    Assertions.assertEquals(
      new BigInteger(1, Arrays.copyOfRange(signature, 0, 32)),
      nonce.getAffineXCoord().toBigInteger()
    );
  }

  private static byte[] padded(byte[] bytes, int offset) {
    byte[] result = new byte[96];
    Arrays.fill(result, (byte) 0xA5);
    System.arraycopy(bytes, 0, result, offset, bytes.length);

    return result;
  }

  private static List<String[]> readVectors() throws Exception {
    List<String[]> vectors = new ArrayList<>();

    try (
      BufferedReader reader = new BufferedReader(
        new InputStreamReader(
          LibBIP340Test.class.getResourceAsStream("/bip340.tsv"),
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
