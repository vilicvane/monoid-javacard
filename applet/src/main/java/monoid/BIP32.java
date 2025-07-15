package monoid;

import javacard.framework.*;
import javacard.security.*;

public final class BIP32 {
  static KeyAgreement keyAgreement;

  static void deriveChildKey(byte[] privateKeyAndChainCode, byte[] path, short pathSegmentOffset,
      byte[] out, short outOffset) {
    short dataOffset = 0;
    byte[] data = JCSystem.makeTransientByteArray(SECP256k1.KEY_BYTES, JCSystem.CLEAR_ON_DESELECT);

    byte[] privateKey = JCSystem.makeTransientByteArray(SECP256k1.KEY_BYTES, JCSystem.CLEAR_ON_DESELECT);

    Util.arrayCopyNonAtomic(privateKeyAndChainCode, (short) 0, privateKey, (short) 0, SECP256k1.KEY_BYTES);

    if (isHardened(path, pathSegmentOffset)) {
      // 0x00 || parent private key

      data[dataOffset++] = 0;
      dataOffset = Util.arrayCopyNonAtomic(privateKey, (short) 0, data, dataOffset, SECP256k1.KEY_BYTES);
    } else {
      // compression flag byte || parent public key

      ECPrivateKey sharedPrivateKey = SECP256k1.getSharedPrivateKey(privateKey, (short) 0);

      dataOffset = SECP256k1.derivePublicKey(sharedPrivateKey, data, dataOffset);
    }

    dataOffset = Util.arrayCopyNonAtomic(path, pathSegmentOffset, data, dataOffset, (short) 4);

    // left 32 bytes for private key & right 32 bytes as chain code
    HmacSHA512.digest(
        privateKeyAndChainCode, (short) 0, SECP256k1.KEY_BYTES,
        data, (short) 0, dataOffset,
        out, outOffset);

    if ((Bytes.add(out, outOffset, privateKey, (short) 0, out, outOffset, SECP256k1.KEY_BYTES) != 0)
        || (Bytes.compare(out, outOffset, SECP256k1.R, (short) 0, SECP256k1.KEY_BYTES) > 0)) {
      Bytes.sub(out, outOffset, SECP256k1.R, (short) 0, out, outOffset, SECP256k1.KEY_BYTES);
    }
  }

  static boolean isHardened(byte[] path, short indexOffset) {
    return (path[indexOffset] & (byte) 0x80) == (byte) 0x80;
  }
}
