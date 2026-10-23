package tests;

import com.licel.jcardsim.base.SimulatorSystem;
import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import java.math.BigInteger;
import javacard.security.ECPrivateKey;
import monoid.CurveException;
import monoid.CurveSECP256k1;
import monoid.CurveSECP256r1;
import monoid.WeierstrassCurve;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class WeierstrassCurveTest {

  @BeforeEach
  public void initialize() {
    CurveException.init();
    WeierstrassCurve.init();
  }

  @AfterEach
  public void dispose() {
    WeierstrassCurve.dispose();
    CurveException.dispose();
  }

  @Test
  public void sharedCurvesAreReusedAndReleasedTogether() {
    Assertions.assertTrue(WeierstrassCurve.secp256k1 instanceof CurveSECP256k1);
    Assertions.assertTrue(WeierstrassCurve.secp256r1 instanceof CurveSECP256r1);

    for (int pass = 0; pass < 2; pass++) {
      Assertions.assertSame(
        WeierstrassCurve.secp256k1,
        WeierstrassCurve.requireSharedCurve(WeierstrassCurve.SECP256k1.clone())
      );
      Assertions.assertSame(
        WeierstrassCurve.secp256r1,
        WeierstrassCurve.requireSharedCurve(WeierstrassCurve.SECP256r1.clone())
      );
    }

    WeierstrassCurve.dispose();

    Assertions.assertNull(WeierstrassCurve.secp256k1);
    Assertions.assertNull(WeierstrassCurve.secp256r1);
    Assertions.assertNull(WeierstrassCurve.getSharedCurve(WeierstrassCurve.SECP256k1));
    Assertions.assertNull(WeierstrassCurve.getSharedCurve(WeierstrassCurve.SECP256r1));
  }

  @Test
  public void operationsReplacePersistentScalarsAfterReset() {
    WeierstrassCurve[] curves = { WeierstrassCurve.secp256k1, WeierstrassCurve.secp256r1 };
    String[] names = { "secp256k1", "secp256r1" };

    for (int index = 0; index < curves.length; index++) {
      WeierstrassCurve curve = curves[index];
      byte[] scalar = new byte[32];
      ECPrivateKey previous = null;

      for (int value = 1; value <= 3; value++) {
        scalar[31] = (byte) value;
        ECPrivateKey key = curve.getSharedPrivateKey(scalar, (short) 0);
        if (previous != null) {
          Assertions.assertSame(previous, key);
        }
        Assertions.assertArrayEquals(
          SECNamedCurves.getByName(names[index])
            .getG()
            .multiply(BigInteger.valueOf(value))
            .getEncoded(true),
          curve.derivePublicKey(key)
        );

        SimulatorSystem.instance().reset();
        Assertions.assertTrue(key.isInitialized());
        previous = key;
      }
    }
  }
}
