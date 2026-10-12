package tests;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javacard.framework.ISOException;
import monoid.CurveED25519;
import monoid.ED25519Key;
import monoid.LibED25519;
import monoid.LibHMACSha512;
import monoid.LibMath;
import monoid.LibSLIP10Ed25519;
import monoid.Signer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class LibED25519Test {

  private CurveED25519 curve;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.bouncycastle.rsa.allow_unsafe_mod", "true");
    LibMath.init();
    curve = new CurveED25519();
  }

  @AfterEach
  public void clear() {
    if (curve != null) {
      curve.clear();
    }

    LibMath.dispose();
  }

  @Test
  public void officialVectors() throws Exception {
    int count = 0;

    for (String[] vector : readVectors()) {
      if (!vector[0].startsWith("RFC8032_")) {
        continue;
      }

      ED25519Key key = curve.getSharedPrivateKey(Hex.decode(vector[1]), (short) 0);
      byte[] message = Hex.decode(vector[4]);

      Assertions.assertArrayEquals(Hex.decode(vector[3]), curve.derivePublicKey(key), vector[0]);
      Assertions.assertArrayEquals(
        Hex.decode(vector[5]),
        Signer.signEDDSAMessage(
          curve,
          key,
          new ByteArraySource(message),
          (short) 0,
          (short) message.length
        ),
        vector[0]
      );
      count++;
    }

    Assertions.assertEquals(5, count);
  }

  @Test
  public void officialVectorsAcrossChunkAndHashBoundaries() throws Exception {
    for (String name : new String[] { "RFC8032_1", "RFC8032_3", "RFC8032_1024" }) {
      String[] vector = requireVector(name);
      ED25519Key key = curve.getSharedPrivateKey(Hex.decode(vector[1]), (short) 0);
      byte[] message = Hex.decode(vector[4]);
      byte[] source = new byte[message.length + 262];
      Arrays.fill(source, (byte) 0xA5);
      System.arraycopy(message, 0, source, 255, message.length);

      for (int chunkLength : new int[] { 127, 128, 129, 256 }) {
        Assertions.assertArrayEquals(
          Hex.decode(vector[5]),
          Signer.signEDDSAMessage(
            curve,
            key,
            new ByteArraySource(source, chunkLength, 7),
            (short) 255,
            (short) message.length
          ),
          name + " with " + chunkLength + " byte chunks"
        );
      }
    }
  }

  @Test
  public void slip10SolanaDerivationAndSignature() throws Exception {
    String[] vector = requireVector("Solana");
    byte[] path = Hex.decode(vector[2]);
    byte[] extendedKey = new byte[64];

    LibHMACSha512.init();

    try {
      byte[] master = LibHMACSha512.digest(
        "ed25519 seed".getBytes(StandardCharsets.US_ASCII),
        Hex.decode(vector[1])
      );

      LibSLIP10Ed25519.derive(
        master,
        (short) 0,
        (short) master.length,
        path,
        (short) 0,
        (short) path.length,
        extendedKey,
        (short) 0
      );
    } finally {
      LibHMACSha512.dispose();
    }

    ED25519Key key = curve.getSharedPrivateKey(extendedKey, (short) 0);
    byte[] message = Hex.decode(vector[4]);

    Assertions.assertEquals(150, message.length);
    Assertions.assertArrayEquals(Hex.decode(vector[3]), curve.derivePublicKey(key));
    Assertions.assertArrayEquals(
      Hex.decode(vector[5]),
      Signer.signEDDSAMessage(
        curve,
        key,
        new ByteArraySource(message),
        (short) 0,
        (short) message.length
      )
    );
  }

  @Test
  public void offsetsAndOverlappingOutput() throws Exception {
    String[] vector = requireVector("RFC8032_2");
    byte[] seed = new byte[40];
    System.arraycopy(Hex.decode(vector[1]), 0, seed, 3, 32);
    ED25519Key key = curve.getSharedPrivateKey(seed, (short) 3);
    byte[] publicKey = new byte[40];

    Assertions.assertEquals(32, curve.derivePublicKey(key, publicKey, (short) 7));
    Assertions.assertArrayEquals(Hex.decode(vector[3]), Arrays.copyOfRange(publicKey, 7, 39));

    byte[] buffer = new byte[100];
    Arrays.fill(buffer, (byte) 0x55);
    buffer[20] = 0x72;

    Assertions.assertArrayEquals(
      Hex.decode(vector[5]),
      Signer.signEDDSAMessage(curve, key, new ByteArraySource(buffer), (short) 20, (short) 1)
    );
    Assertions.assertEquals(
      64,
      LibED25519.sign(
        curve,
        key,
        new ByteArraySource(buffer),
        (short) 20,
        (short) 1,
        buffer,
        (short) 5
      )
    );
    Assertions.assertArrayEquals(Hex.decode(vector[5]), Arrays.copyOfRange(buffer, 5, 69));

    for (int i = 0; i < buffer.length; i++) {
      if (i < 5 || i >= 69) {
        Assertions.assertEquals((byte) 0x55, buffer[i]);
      }
    }
  }

  @Test
  public void clearedKeysRequireNewImport() throws Exception {
    String[] first = requireVector("RFC8032_1");
    ED25519Key key = curve.getSharedPrivateKey(Hex.decode(first[1]), (short) 0);
    key.clear();

    Assertions.assertThrows(ISOException.class, () ->
      Signer.signEDDSAMessage(curve, key, new ByteArraySource(new byte[0]), (short) 0, (short) 0)
    );
    Assertions.assertThrows(ISOException.class, () -> curve.derivePublicKey(key));

    String[] second = requireVector("RFC8032_2");
    ED25519Key imported = curve.getSharedPrivateKey(Hex.decode(second[1]), (short) 0);
    byte[] message = Hex.decode(second[4]);

    Assertions.assertArrayEquals(
      Hex.decode(second[5]),
      Signer.signEDDSAMessage(
        curve,
        imported,
        new ByteArraySource(message),
        (short) 0,
        (short) message.length
      )
    );

    ED25519Key replacement = curve.getSharedPrivateKey(Hex.decode(first[1]), (short) 0);

    Assertions.assertThrows(ISOException.class, () ->
      Signer.signEDDSAMessage(
        curve,
        imported,
        new ByteArraySource(new byte[0]),
        (short) 0,
        (short) 0
      )
    );
    Assertions.assertArrayEquals(
      Hex.decode(first[5]),
      Signer.signEDDSAMessage(
        curve,
        replacement,
        new ByteArraySource(new byte[0]),
        (short) 0,
        (short) 0
      )
    );

    curve.clear();

    Assertions.assertThrows(ISOException.class, () ->
      Signer.signEDDSAMessage(
        curve,
        replacement,
        new ByteArraySource(new byte[0]),
        (short) 0,
        (short) 0
      )
    );
  }

  @Test
  public void rejectsKeysFromAnotherCurve() throws Exception {
    String[] vector = requireVector("RFC8032_1");
    ED25519Key key = curve.getSharedPrivateKey(Hex.decode(vector[1]), (short) 0);
    CurveED25519 other = new CurveED25519();

    try {
      Assertions.assertThrows(ISOException.class, () ->
        Signer.signEDDSAMessage(other, key, new ByteArraySource(new byte[0]), (short) 0, (short) 0)
      );
      Assertions.assertThrows(ISOException.class, () -> other.derivePublicKey(key));
    } finally {
      other.clear();
    }

    Assertions.assertArrayEquals(
      Hex.decode(vector[5]),
      Signer.signEDDSAMessage(curve, key, new ByteArraySource(new byte[0]), (short) 0, (short) 0)
    );
  }

  @Test
  public void failedSignatureCanBeRetried() throws Exception {
    String[] vector = requireVector("RFC8032_2");
    ED25519Key key = curve.getSharedPrivateKey(Hex.decode(vector[1]), (short) 0);
    byte[] message = Hex.decode(vector[4]);

    Assertions.assertThrows(RuntimeException.class, () ->
      LibED25519.sign(
        curve,
        key,
        new ByteArraySource(message),
        (short) 0,
        (short) message.length,
        new byte[63],
        (short) 0
      )
    );

    byte[] signature = new byte[64];

    Assertions.assertEquals(
      64,
      LibED25519.sign(
        curve,
        key,
        new ByteArraySource(message),
        (short) 0,
        (short) message.length,
        signature,
        (short) 0
      )
    );
    Assertions.assertArrayEquals(Hex.decode(vector[5]), signature);
  }

  private static String[] requireVector(String name) throws Exception {
    for (String[] vector : readVectors()) {
      if (vector[0].equals(name)) {
        return vector;
      }
    }

    throw new IllegalArgumentException("Missing Ed25519 vector: " + name);
  }

  private static List<String[]> readVectors() throws Exception {
    List<String[]> vectors = new ArrayList<>();

    try (
      BufferedReader reader = new BufferedReader(
        new InputStreamReader(
          LibED25519Test.class.getResourceAsStream("/ed25519.tsv"),
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
