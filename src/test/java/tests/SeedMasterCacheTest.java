package tests;

import com.licel.jcardsim.smartcardio.CardSimulator;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import monoid.BIP32Derivation;
import monoid.KeyDerivation;
import monoid.LibHMACSha512;
import monoid.Monoid001Derivation;
import monoid.SLIP10Ed25519Derivation;
import monoid.WeierstrassCurve;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SeedMasterCacheTest {

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    simulator = new CardSimulator();
    LibHMACSha512.init();
    KeyDerivation.init();
    WeierstrassCurve.init();
  }

  @AfterEach
  public void dispose() {
    WeierstrassCurve.dispose();
    KeyDerivation.dispose();
    LibHMACSha512.dispose();
  }

  @Test
  public void sharedMastersMatchIndependentExtractForAllDeriversAcrossReset() throws Exception {
    KeyDerivation[] derivations = {
      new BIP32Derivation(),
      new SLIP10Ed25519Derivation(),
      new Monoid001Derivation(WeierstrassCurve.SECP256r1),
    };
    String[] labels = { "Bitcoin seed", "ed25519 seed", "Monoid-001" };
    byte[] seed = new byte[64];

    for (int source = 0; source < 2; source++) {
      Arrays.fill(seed, (byte) (source + 1));
      for (int algorithm = 0; algorithm < derivations.length; algorithm++) {
        KeyDerivation derivation = derivations[algorithm];
        Mac extract = Mac.getInstance("HmacSHA512");
        extract.init(
          new SecretKeySpec(labels[algorithm].getBytes(StandardCharsets.US_ASCII), "HmacSHA512")
        );
        byte[] master = extract.doFinal(seed);
        byte[] originalMaster = master.clone();
        byte[] originalSeed = seed.clone();

        for (int branch = 0; branch < 2; branch++) {
          byte[] path = algorithm == 2
            ? new byte[] { (byte) branch }
            : new byte[] { (byte) 0x80, 0, 0, (byte) branch };
          byte[] expected = derivation.derive(master, path).getKey().clone();
          Assertions.assertArrayEquals(expected, derivation.deriveFromSeed(seed, path).getKey());
          simulator.reset();
          Assertions.assertArrayEquals(expected, derivation.deriveFromSeed(seed, path).getKey());
          Assertions.assertArrayEquals(originalMaster, master);
          Assertions.assertArrayEquals(originalSeed, seed);
        }
      }
    }
  }
}
