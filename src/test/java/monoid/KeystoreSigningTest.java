package monoid;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.bouncycastle.crypto.params.ECDomainParameters;
import com.licel.jcardsim.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.licel.jcardsim.bouncycastle.crypto.signers.ECDSASigner;
import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class KeystoreSigningTest {

  private Keystore keystore;

  @BeforeEach
  public void initialize() {
    LibHMACSha512.init();
    KeyDerivation.init();
    WeierstrassCurve.init();
    keystore = new Keystore(null);
  }

  @AfterEach
  public void dispose() {
    WeierstrassCurve.dispose();
    KeyDerivation.dispose();
    LibHMACSha512.dispose();
  }

  @Test
  public void reusedSignerRefreshesKeyAndDigestWhilePreservingCachedInputs() {
    byte[] seed = new byte[64];
    byte[] context = { 3, 7, 11 };
    byte[] digest = new byte[48];
    byte[] reused = null;

    for (short iteration = 0; iteration < 6; iteration++) {
      seed[0] = (byte) (iteration % 2);
      context[0] = (byte) (iteration % 3);
      for (short index = 0; index < digest.length; index++) {
        digest[index] = (byte) (index + iteration * 17);
      }
      byte[] expectedSeed = seed.clone();
      byte[] expectedContext = context.clone();
      byte[] expectedDigest = digest.clone();
      byte[] publicKey = keystore.getMonoid001UncompressedPublicKey(seed, context).clone();

      byte[] signature = keystore.signMonoid001ECDSADigest(seed, context, digest, (short) 7);
      if (reused != null) {
        Assertions.assertSame(reused, signature);
      }
      reused = signature;
      assertSignature(publicKey, Arrays.copyOfRange(digest, 7, 39), signature);
      Assertions.assertArrayEquals(expectedSeed, seed);
      Assertions.assertArrayEquals(expectedContext, context);
      Assertions.assertArrayEquals(expectedDigest, digest);
      Assertions.assertArrayEquals(
        publicKey,
        keystore.getMonoid001UncompressedPublicKey(seed, context)
      );
    }
  }

  @Test
  public void signingRecoversAfterAnInvalidDigestRange() {
    byte[] seed = new byte[64];
    byte[] context = { 1 };
    byte[] digest = new byte[32];
    byte[] publicKey = keystore.getMonoid001UncompressedPublicKey(seed, context).clone();
    byte[] signature = keystore.signMonoid001ECDSADigest(seed, context, digest);
    assertSignature(publicKey, digest, signature);

    Assertions.assertThrows(RuntimeException.class, () ->
      keystore.signMonoid001ECDSADigest(seed, context, digest, (short) 1)
    );
    digest[0] = 1;
    Assertions.assertSame(signature, keystore.signMonoid001ECDSADigest(seed, context, digest));
    assertSignature(publicKey, digest, signature);
  }

  private static void assertSignature(byte[] point, byte[] digest, byte[] signature) {
    X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
    ECDomainParameters parameters = new ECDomainParameters(
      curve.getCurve(),
      curve.getG(),
      curve.getN(),
      curve.getH()
    );
    ECDSASigner verifier = new ECDSASigner();
    verifier.init(
      false,
      new ECPublicKeyParameters(curve.getCurve().decodePoint(point), parameters)
    );
    BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));
    Assertions.assertTrue(verifier.verifySignature(digest, r, s));
    Assertions.assertTrue(s.compareTo(curve.getN().shiftRight(1)) <= 0);
    byte[] changedDigest = digest.clone();
    changedDigest[0] ^= 1;
    Assertions.assertFalse(verifier.verifySignature(changedDigest, r, s));
  }
}
