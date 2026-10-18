package tests;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import monoid.BIP32Derivation;
import monoid.CurveException;
import monoid.KeyDerivation;
import monoid.WeierstrassCurve;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class BIP32DerivationTest {

  private BIP32Derivation derivation;

  @BeforeEach
  public void initialize() {
    CurveException.init();
    WeierstrassCurve.init();
    KeyDerivation.init();
    derivation = new BIP32Derivation();
  }

  @AfterEach
  public void dispose() {
    KeyDerivation.dispose();
    WeierstrassCurve.dispose();
    CurveException.dispose();
  }

  @Test
  public void rejectsP256ForEmptyAndNonemptyPaths() {
    byte[] master = new byte[64];
    master[31] = 1;
    byte[] original = master.clone();

    for (byte[] path : new byte[][] {
      new byte[0],
      Hex.decode("00000000"),
      Hex.decode("80000000"),
    }) {
      CurveException exception = Assertions.assertThrows(CurveException.class, () ->
        derivation.derive(WeierstrassCurve.secp256r1, master, path).getKey()
      );

      Assertions.assertEquals(CurveException.REASON_UNSUPPORTED_CURVE, exception.getReason());
      exception = Assertions.assertThrows(CurveException.class, () ->
        derivation.deriveFromSeed(WeierstrassCurve.secp256r1, master, path)
      );
      Assertions.assertEquals(CurveException.REASON_UNSUPPORTED_CURVE, exception.getReason());
      Assertions.assertArrayEquals(original, master);
    }

    byte[] derived = derivation.derive(WeierstrassCurve.secp256k1, master, new byte[0]).getKey();

    Assertions.assertArrayEquals(original, derived);
    Assertions.assertNotSame(master, derived);
  }
}
