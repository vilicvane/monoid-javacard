package monoididentity;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPublicKey;
import javacard.security.Signature;

/** Verifies the Authority service's challenge-bound time proof without retaining caller state. */
final class AuthorityTime {

  private static final byte VERSION = 1;

  private static final short DATA_LENGTH = 41;
  private static final short CHALLENGE_OFFSET = 9;
  private static final short CHALLENGE_LENGTH = 32;
  private static final short SIGNATURE_LENGTH = 64;
  private static final short SCALAR_LENGTH = 32;
  private static final short MAX_DER_LENGTH = 72;

  // @formatter:off
  private static final byte[] CONTEXT = {'M','o','n','o','i','d',' ','A','u','t','h','o','r','i','t','y',' ','T','i','m','e'};
  // @formatter:on

  private final ECPublicKey authority;
  private final Signature verifier;

  private final byte[] der = new byte[MAX_DER_LENGTH];

  AuthorityTime(ECPublicKey authority) {
    this.authority = authority;

    // Identity verifies while the calling applet remains selected.
    verifier = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, true);
  }

  void verify(byte[] data, byte[] signature, byte[] challenge) {
    if (
      data == null ||
      data.length != DATA_LENGTH ||
      data[0] != VERSION ||
      signature == null ||
      signature.length != SIGNATURE_LENGTH ||
      challenge == null ||
      challenge.length != CHALLENGE_LENGTH
    ) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    if (Util.arrayCompare(data, CHALLENGE_OFFSET, challenge, (short) 0, CHALLENGE_LENGTH) != 0) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    short length = writeScalar(signature, (short) 0, der, (short) 2);
    length = writeScalar(signature, SCALAR_LENGTH, der, length);

    der[0] = 0x30;
    der[1] = (byte) (length - 2);

    try {
      verifier.init(authority, Signature.MODE_VERIFY);
      verifier.update(CONTEXT, (short) 0, (short) CONTEXT.length);

      if (!verifier.verify(data, (short) 0, DATA_LENGTH, der, (short) 0, length)) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }
    } catch (CryptoException exception) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  private static short writeScalar(byte[] raw, short offset, byte[] output, short dest) {
    short end = (short) (offset + SCALAR_LENGTH);

    // DER INTEGER removes unsigned leading zeros, but retains one byte for zero itself.
    while (offset < (short) (end - 1) && raw[offset] == 0) {
      offset++;
    }

    short length = (short) (end - offset);
    boolean leadingZero = (raw[offset] & 0x80) != 0;

    output[dest++] = 0x02;
    output[dest++] = (byte) (length + (leadingZero ? 1 : 0));

    if (leadingZero) {
      output[dest++] = 0;
    }

    Util.arrayCopyNonAtomic(raw, offset, output, dest, length);

    return (short) (dest + length);
  }
}
