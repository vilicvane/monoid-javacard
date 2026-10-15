package tests;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.util.BigIntegers;
import java.math.BigInteger;
import java.util.Arrays;
import monoid.LibECDSA;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LibECDSATest {

  @Test
  public void lowSUsesTheCurveOrderAndPreservesOtherBytes() {
    for (String name : new String[] { "secp256k1", "secp256r1" }) {
      BigInteger order = SECNamedCurves.getByName(name).getN();
      byte[] orderBytes = BigIntegers.asUnsignedByteArray(32, order);
      byte[] originalOrder = orderBytes.clone();
      BigInteger halfOrder = order.shiftRight(1);

      for (BigInteger s : new BigInteger[] {
        BigInteger.ONE,
        halfOrder,
        halfOrder.add(BigInteger.ONE),
        order.subtract(BigInteger.ONE),
      }) {
        for (short offset : new short[] { 0, 3 }) {
          byte[] signature = new byte[offset + 64 + 2];
          Arrays.fill(signature, (byte) 0x5A);
          System.arraycopy(BigIntegers.asUnsignedByteArray(32, s), 0, signature, offset + 32, 32);
          byte[] expected = signature.clone();
          BigInteger expectedS = s.min(order.subtract(s));
          System.arraycopy(
            BigIntegers.asUnsignedByteArray(32, expectedS),
            0,
            expected,
            offset + 32,
            32
          );

          LibECDSA.ensureLowS(orderBytes, signature, offset);

          Assertions.assertArrayEquals(expected, signature, name);
          Assertions.assertArrayEquals(originalOrder, orderBytes, name);
        }
      }
    }
  }
}
