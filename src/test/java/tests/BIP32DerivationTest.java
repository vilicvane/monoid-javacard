package tests;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Arrays;
import javacard.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import monoid.BIP32Derivation;
import monoid.CurveException;
import monoid.KeyDerivation;
import monoid.LibHMACSha512;
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
    LibHMACSha512.init();
    KeyDerivation.init();
    derivation = new BIP32Derivation();
  }

  @AfterEach
  public void dispose() {
    KeyDerivation.dispose();
    LibHMACSha512.dispose();
    WeierstrassCurve.dispose();
    CurveException.dispose();
  }

  @Test
  public void mixedPathsPreserveParentInputsWithBothHMACBackends() throws Exception {
    byte[] master = Hex.decode(
      "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35" +
      "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    );
    byte[] path = Hex.decode("800000000000000180000002");
    byte[] originalMaster = master.clone();
    byte[] originalPath = path.clone();
    byte[] expected = reference(master, path);

    for (boolean software : new boolean[] { false, true }) {
      if (software) {
        LibHMACSha512.dispose();
        Field digest = LibHMACSha512.class.getDeclaredField("sharedDigest");
        digest.setAccessible(true);
        digest.set(null, MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false));
        KeyDerivation.clearCache();
      }
      byte[] actual = derivation.derive(WeierstrassCurve.secp256k1, master, path).getKey();
      Assertions.assertArrayEquals(expected, actual);
      Assertions.assertArrayEquals(originalMaster, master);
      Assertions.assertArrayEquals(originalPath, path);
      actual[0] ^= 1;
      Assertions.assertArrayEquals(
        expected,
        derivation.derive(WeierstrassCurve.secp256k1, master, path).getKey()
      );
    }
  }

  private byte[] reference(byte[] master, byte[] path) throws Exception {
    X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
    byte[] key = master.clone();
    for (int offset = 0; offset < path.length; offset += 4) {
      BigInteger parent = new BigInteger(1, Arrays.copyOf(key, 32));
      byte[] data = new byte[37];
      if ((path[offset] & 0x80) != 0) {
        System.arraycopy(key, 0, data, 1, 32);
      } else {
        System.arraycopy(curve.getG().multiply(parent).getEncoded(true), 0, data, 0, 33);
      }
      System.arraycopy(path, offset, data, 33, 4);
      Mac hmac = Mac.getInstance("HmacSHA512");
      hmac.init(new SecretKeySpec(Arrays.copyOfRange(key, 32, 64), "HmacSHA512"));
      key = hmac.doFinal(data);
      byte[] child = new BigInteger(1, Arrays.copyOf(key, 32))
        .add(parent)
        .mod(curve.getN())
        .toByteArray();
      Arrays.fill(key, 0, 32, (byte) 0);
      int length = Math.min(32, child.length);
      System.arraycopy(child, child.length - length, key, 32 - length, length);
    }
    return key;
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
