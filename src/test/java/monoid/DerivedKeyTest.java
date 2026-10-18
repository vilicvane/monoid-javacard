package monoid;

import com.licel.jcardsim.base.SimulatorSystem;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.util.Arrays;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.ECPrivateKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tests.ByteArraySource;

public class DerivedKeyTest {

  // RFC 8032 section 7.1, test 2.
  private static final byte[] SEED = Hex.decode(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
  );
  private static final byte[] PUBLIC_KEY = Hex.decode(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
  );
  private static final byte[] MESSAGE = Hex.decode("72");
  private static final byte[] SIGNATURE = Hex.decode(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
  );

  private CountingEdwardsCurve curve;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.bouncycastle.rsa.allow_unsafe_mod", "true");
    LibMath.init();
    curve = new CountingEdwardsCurve();
  }

  @AfterEach
  public void clear() {
    curve.clear();
    LibMath.dispose();
  }

  @Test
  public void keepsKeyMaterialIndependentFromInputAndReturnedCopies() {
    byte[] input = new byte[64];
    for (int index = 0; index < input.length; index++) {
      input[index] = (byte) index;
    }
    byte[] expected = input.clone();
    DerivedKey key = new DerivedKey(input);

    Arrays.fill(input, (byte) 0);
    byte[] first = key.getKey();
    Assertions.assertArrayEquals(expected, first);
    Assertions.assertEquals(JCSystem.CLEAR_ON_DESELECT, JCSystem.isTransient(first));
    Arrays.fill(first, (byte) 0);

    byte[] second = key.getKey();
    Assertions.assertNotSame(first, second);
    Assertions.assertArrayEquals(expected, second);

    SimulatorSystem.instance().reset();

    Assertions.assertArrayEquals(new byte[64], second);
    Assertions.assertArrayEquals(expected, key.getKey());
  }

  @Test
  public void restoresExpandedKeyForSigningAfterViewAndReset() {
    DerivedKey key = new DerivedKey(SEED);
    ED25519Key viewKey = curve.getSharedPrivateKey(key);
    byte[] publicKey = curve.derivePublicKey(viewKey);

    Assertions.assertArrayEquals(PUBLIC_KEY, publicKey);
    Assertions.assertEquals(1, curve.imports);
    Assertions.assertEquals(1, curve.multiplications);
    publicKey[0] ^= 1;
    viewKey.clear();
    Assertions.assertThrows(ISOException.class, () -> curve.derivePublicKey(viewKey));

    ED25519Key signingKey = curve.getSharedPrivateKey(key);

    Assertions.assertNotSame(viewKey, signingKey);
    Assertions.assertEquals(1, curve.imports);
    Assertions.assertEquals(1, curve.multiplications);
    Assertions.assertArrayEquals(PUBLIC_KEY, curve.derivePublicKey(signingKey));
    Assertions.assertArrayEquals(SIGNATURE, sign(signingKey, MESSAGE));
    // The cached public key skips expansion, but each signature still computes its nonce point.
    Assertions.assertEquals(2, curve.multiplications);

    SimulatorSystem.instance().reset();

    Assertions.assertThrows(ISOException.class, () -> curve.derivePublicKey(signingKey));
    Assertions.assertThrows(ISOException.class, () -> sign(signingKey, MESSAGE));
    ED25519Key restored = curve.getSharedPrivateKey(key);

    Assertions.assertNotSame(signingKey, restored);
    Assertions.assertEquals(1, curve.imports);
    Assertions.assertEquals(2, curve.multiplications);
    Assertions.assertArrayEquals(PUBLIC_KEY, curve.derivePublicKey(restored));
    Assertions.assertArrayEquals(SIGNATURE, sign(restored, MESSAGE));
    Assertions.assertEquals(3, curve.multiplications);

    curve.clear();

    Assertions.assertThrows(ISOException.class, () -> curve.derivePublicKey(restored));
    Assertions.assertArrayEquals(PUBLIC_KEY, curve.derivePublicKey(curve.getSharedPrivateKey(key)));
    Assertions.assertEquals(1, curve.imports);
    Assertions.assertEquals(3, curve.multiplications);
  }

  @Test
  public void keepsExpandedKeysSeparateWhenSwitchingBetweenSeeds() {
    // RFC 8032 section 7.1, test 1.
    DerivedKey first = new DerivedKey(
      Hex.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    );
    byte[] expectedPublicKey = Hex.decode(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    byte[] expectedSignature = Hex.decode(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    DerivedKey second = new DerivedKey(SEED);
    ED25519Key firstKey = curve.getSharedPrivateKey(first);

    Assertions.assertArrayEquals(expectedPublicKey, curve.derivePublicKey(firstKey));
    ED25519Key secondKey = curve.getSharedPrivateKey(second);
    Assertions.assertArrayEquals(PUBLIC_KEY, curve.derivePublicKey(secondKey));
    Assertions.assertThrows(ISOException.class, () -> curve.derivePublicKey(firstKey));
    Assertions.assertEquals(2, curve.imports);
    Assertions.assertEquals(2, curve.multiplications);

    ED25519Key restored = curve.getSharedPrivateKey(first);

    Assertions.assertThrows(ISOException.class, () -> curve.derivePublicKey(secondKey));
    Assertions.assertEquals(2, curve.imports);
    Assertions.assertEquals(2, curve.multiplications);
    Assertions.assertArrayEquals(expectedPublicKey, curve.derivePublicKey(restored));
    Assertions.assertArrayEquals(expectedSignature, sign(restored, new byte[0]));
    Assertions.assertEquals(3, curve.multiplications);
  }

  @Test
  public void computesWeierstrassPublicKeyOnceAndReturnsIndependentCopies() {
    CountingWeierstrassCurve curve = new CountingWeierstrassCurve();
    byte[] scalar = new byte[32];
    scalar[31] = 1;
    DerivedKey key = new DerivedKey(scalar);
    byte[] expected = Hex.decode(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
    byte[] first = key.getPublicKey(curve);

    Assertions.assertArrayEquals(expected, first);
    Assertions.assertEquals(JCSystem.CLEAR_ON_DESELECT, JCSystem.isTransient(first));
    Assertions.assertEquals(1, curve.imports);
    Assertions.assertEquals(1, curve.publicKeys);
    first[0] ^= 1;

    byte[] second = key.getPublicKey(curve);

    Assertions.assertNotSame(first, second);
    Assertions.assertArrayEquals(expected, second);
    Assertions.assertEquals(JCSystem.CLEAR_ON_DESELECT, JCSystem.isTransient(second));
    Arrays.fill(second, (byte) 0);

    SimulatorSystem.instance().reset();

    Assertions.assertArrayEquals(expected, key.getPublicKey(curve));
    Assertions.assertEquals(1, curve.imports);
    Assertions.assertEquals(1, curve.publicKeys);
  }

  private byte[] sign(ED25519Key key, byte[] message) {
    return Signer.signED25519Message(
      curve,
      key,
      new ByteArraySource(message),
      (short) 0,
      (short) message.length
    );
  }

  private static class CountingEdwardsCurve extends CurveED25519 {

    int imports;
    int multiplications;

    @Override
    public ED25519Key getSharedPrivateKey(byte[] in, short keyOffset) {
      imports++;
      return super.getSharedPrivateKey(in, keyOffset);
    }

    @Override
    void multiplyBase(byte[] scalar, byte[] out, short outOffset) {
      multiplications++;
      super.multiplyBase(scalar, out, outOffset);
    }
  }

  private static class CountingWeierstrassCurve extends CurveSECP256k1 {

    int imports;
    int publicKeys;

    @Override
    public ECPrivateKey getSharedPrivateKey(byte[] in, short keyOffset) {
      imports++;
      return super.getSharedPrivateKey(in, keyOffset);
    }

    @Override
    public short derivePublicKey(ECPrivateKey privateKey, byte[] out, short outOffset) {
      publicKeys++;
      return super.derivePublicKey(privateKey, out, outOffset);
    }
  }
}
