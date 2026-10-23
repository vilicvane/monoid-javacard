package main;

import com.licel.jcardsim.bouncycastle.asn1.ASN1Integer;
import com.licel.jcardsim.bouncycastle.asn1.ASN1Sequence;
import java.util.Arrays;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.Signature;

/** Host-only equivalent of Signature.OneShot's PLAIN precomputed ECDSA operation. */
public final class SimulatorECDSA {

  public static byte[] sign(byte cipher, Key privateKey, byte[] digest) {
    if (cipher != Signature.SIG_CIPHER_ECDSA_PLAIN) {
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }

    Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    signature.init(privateKey, Signature.MODE_SIGN);
    byte[] raw = new byte[64];
    signPreComputedHash(signature, digest, (short) 0, (short) digest.length, raw, (short) 0);
    return raw;
  }

  /** Keep the reused native engine's init/sign lifecycle while adapting only its output format. */
  public static short signPreComputedHash(
    Signature signature,
    byte[] digest,
    short digestOffset,
    short digestLength,
    byte[] out,
    short outOffset
  ) {
    byte[] der = new byte[signature.getLength()];
    short length = signature.signPreComputedHash(
      digest,
      digestOffset,
      digestLength,
      der,
      (short) 0
    );
    ASN1Sequence values = ASN1Sequence.getInstance(Arrays.copyOf(der, length));
    Arrays.fill(out, outOffset, outOffset + 64, (byte) 0);

    for (int index = 0; index < 2; index++) {
      byte[] value = ASN1Integer.getInstance(values.getObjectAt(index))
        .getPositiveValue()
        .toByteArray();
      int count = Math.min(value.length, 32);
      System.arraycopy(
        value,
        value.length - count,
        out,
        outOffset + index * 32 + 32 - count,
        count
      );
    }

    return 64;
  }
}
