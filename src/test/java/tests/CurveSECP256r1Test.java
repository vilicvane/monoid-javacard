package tests;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.math.BigInteger;
import java.util.Arrays;
import javacard.security.ECPrivateKey;
import monoid.CurveSECP256r1;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CurveSECP256r1Test {

  @Test
  public void parametersMatchSECP256r1() {
    X9ECParameters parameters = SECNamedCurves.getByName("secp256r1");
    CurveSECP256r1 curve = new CurveSECP256r1();

    Assertions.assertEquals(
      parameters.getCurve().getField().getCharacteristic(),
      new BigInteger(1, CurveSECP256r1.FP)
    );
    Assertions.assertEquals(
      parameters.getCurve().getA().toBigInteger(),
      new BigInteger(1, CurveSECP256r1.A)
    );
    Assertions.assertEquals(
      parameters.getCurve().getB().toBigInteger(),
      new BigInteger(1, CurveSECP256r1.B)
    );
    Assertions.assertArrayEquals(parameters.getG().getEncoded(false), CurveSECP256r1.G);
    Assertions.assertEquals(parameters.getN(), new BigInteger(1, curve.getR()));
    Assertions.assertEquals(parameters.getH().intValue(), CurveSECP256r1.K);
    Assertions.assertEquals(32, curve.getKeyLength());
    Assertions.assertEquals(33, curve.getPublicKeyLength());
  }

  @Test
  public void publicKeysMatchVectorsWithOffsetsAndSharedKeyReinitialization() {
    // SEC 2 v2 section 2.4.2: G and -G; RFC 6979 appendix A.2.5: key pair.
    String[][] vectors = {
      {
        "0000000000000000000000000000000000000000000000000000000000000001",
        "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
      },
      {
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550",
        "026B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
      },
      {
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        "0360FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
      },
    };
    CurveSECP256r1 curve = new CurveSECP256r1();
    ECPrivateKey sharedPrivateKey = null;

    for (int pass = 0; pass < 2; pass++) {
      for (String[] vector : vectors) {
        for (short offset : new short[] { 0, 3 }) {
          byte[] input = new byte[offset + 32 + 2];
          Arrays.fill(input, (byte) 0x5A);
          System.arraycopy(Hex.decode(vector[0]), 0, input, offset, 32);
          byte[] originalInput = input.clone();
          ECPrivateKey privateKey = curve.getSharedPrivateKey(input, offset);

          if (sharedPrivateKey != null) {
            Assertions.assertSame(sharedPrivateKey, privateKey);
          }

          sharedPrivateKey = privateKey;
          byte[] output = new byte[37];
          Arrays.fill(output, (byte) 0x5A);
          byte[] expected = output.clone();
          System.arraycopy(Hex.decode(vector[1]), 0, expected, 2, 33);

          Assertions.assertEquals(33, curve.derivePublicKey(privateKey, output, (short) 2));
          Assertions.assertArrayEquals(expected, output);
          Assertions.assertArrayEquals(Hex.decode(vector[1]), curve.derivePublicKey(privateKey));
          Assertions.assertArrayEquals(originalInput, input);
        }
      }

      sharedPrivateKey.clearKey();
      Assertions.assertFalse(sharedPrivateKey.isInitialized());
    }
  }
}
