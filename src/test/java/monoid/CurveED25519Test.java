package monoid;

import com.licel.jcardsim.base.SimulatorSystem;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.util.Arrays;
import javacard.framework.ISOException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tests.ByteArraySource;

public class CurveED25519Test {

  private CurveED25519 curve;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.bouncycastle.rsa.allow_unsafe_mod", "true");
    LibMath.init();
    curve = new CurveED25519();
  }

  @AfterEach
  public void clear() {
    curve.clear();
    LibMath.dispose();
  }

  @Test
  public void baseMultiplicationMatchesEdwardsArithmeticAtScalarBoundaries() {
    // Big-endian scalars and compressed Edwards points generated independently
    // with Bouncy Castle 1.66 Ed25519.scalarMultBaseEncoded: 0, 1, 2, r - 1, arbitrary.
    String[][] vectors = {
      {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
      },
      {
        "0000000000000000000000000000000000000000000000000000000000000001",
        "5866666666666666666666666666666666666666666666666666666666666666",
      },
      {
        "0000000000000000000000000000000000000000000000000000000000000002",
        "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
      },
      {
        "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ec",
        "58666666666666666666666666666666666666666666666666666666666666e6",
      },
      {
        "0c67ba4d98328fd7005b2d1a269a4405f873c26cb91690c6bf7c7183993e8719",
        "ec6f86b23a3c12a907c444ebcd507df725391aa4403a22be028c81928ee3e484",
      },
    };

    for (String[] vector : vectors) {
      byte[] scalar = Hex.decode(vector[0]);
      byte[] before = scalar.clone();
      byte[] out = new byte[40];
      Arrays.fill(out, (byte) 0xA5);

      curve.multiplyBase(scalar, out, (short) 3);

      Assertions.assertArrayEquals(
        Hex.decode(vector[1]),
        Arrays.copyOfRange(out, 3, 35),
        vector[0]
      );
      Assertions.assertArrayEquals(before, scalar);
      Assertions.assertArrayEquals(
        new byte[] { (byte) 0xA5, (byte) 0xA5, (byte) 0xA5 },
        Arrays.copyOfRange(out, 0, 3)
      );
      Assertions.assertArrayEquals(
        new byte[] { (byte) 0xA5, (byte) 0xA5, (byte) 0xA5, (byte) 0xA5, (byte) 0xA5 },
        Arrays.copyOfRange(out, 35, 40)
      );
    }
  }

  @Test
  public void signingReusesScratchAndRequiresReimportAfterReset() throws Exception {
    // RFC 8032 section 7.1, test 2.
    byte[] seed = Hex.decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    byte[] message = Hex.decode("72");
    byte[] expectedPublicKey = Hex.decode(
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    );
    byte[] expectedSignature = Hex.decode(
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );
    ED25519Key key = curve.getSharedPrivateKey(seed, (short) 0);
    byte[] signature = new byte[64];

    for (int iteration = 0; iteration < 3; iteration++) {
      Assertions.assertArrayEquals(expectedPublicKey, curve.derivePublicKey(key));
      LibED25519.sign(
        curve,
        key,
        new ByteArraySource(message),
        (short) 0,
        (short) message.length,
        signature,
        (short) 0
      );
      Assertions.assertArrayEquals(expectedSignature, signature);
    }

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

    // Reset clears transient data, while the shared curve remains reachable.
    SimulatorSystem.instance().reset();

    Assertions.assertThrows(ISOException.class, () -> curve.derivePublicKey(key));
    Assertions.assertThrows(ISOException.class, () ->
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

    ED25519Key imported = curve.getSharedPrivateKey(seed, (short) 0);
    LibED25519.sign(
      curve,
      imported,
      new ByteArraySource(message),
      (short) 0,
      (short) message.length,
      signature,
      (short) 0
    );

    Assertions.assertArrayEquals(expectedPublicKey, curve.derivePublicKey(imported));
    Assertions.assertArrayEquals(expectedSignature, signature);
  }
}
