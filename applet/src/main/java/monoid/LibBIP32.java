package monoid;

import javacard.framework.*;
import javacard.security.*;

public final class LibBIP32 {
  public static void deriveChildKey(byte[] privateKeyAndChainCode, byte[] path, short pathSegmentOffset) {
    byte[] data = JCSystem.makeTransientByteArray((short) (1 + LibSECP256k1.KEY_BYTES + 4), JCSystem.CLEAR_ON_DESELECT);
    short dataOffset = 0;

    byte[] currentPrivateKeyAndChainCode = JCSystem.makeTransientByteArray((short) (LibSECP256k1.KEY_BYTES * 2),
        JCSystem.CLEAR_ON_DESELECT);

    Util.arrayCopyNonAtomic(privateKeyAndChainCode, (short) 0, currentPrivateKeyAndChainCode, (short) 0,
        (short) (LibSECP256k1.KEY_BYTES * 2));

    if (isHardened(path, pathSegmentOffset)) {
      // 0x00 || parent private key

      data[dataOffset++] = 0;
      dataOffset = Util.arrayCopyNonAtomic(currentPrivateKeyAndChainCode, (short) 0, data, dataOffset,
          LibSECP256k1.KEY_BYTES);
    } else {
      // compression flag byte || parent public key

      ECPrivateKey sharedPrivateKey = LibSECP256k1.getSharedPrivateKey(currentPrivateKeyAndChainCode, (short) 0);

      dataOffset += LibSECP256k1.derivePublicKey(sharedPrivateKey, data, dataOffset);
    }

    dataOffset = Util.arrayCopyNonAtomic(path, pathSegmentOffset, data, dataOffset, (short) 4);

    // left 32 bytes for private key & right 32 bytes as chain code
    LibHMACSha512.digest(
        currentPrivateKeyAndChainCode, LibSECP256k1.KEY_BYTES, LibSECP256k1.KEY_BYTES,
        data, (short) 0, (short) data.length,
        privateKeyAndChainCode, (short) 0);

    if (LibBytesMath.add(
        privateKeyAndChainCode, (short) 0,
        currentPrivateKeyAndChainCode, (short) 0,
        privateKeyAndChainCode, (short) 0, LibSECP256k1.KEY_BYTES) != 0
        || LibBytesMath.compare(privateKeyAndChainCode, (short) 0, LibSECP256k1.R, (short) 0,
            LibSECP256k1.KEY_BYTES) > 0) {

      LibBytesMath.sub(privateKeyAndChainCode, (short) 0, LibSECP256k1.R, (short) 0, privateKeyAndChainCode, (short) 0,
          LibSECP256k1.KEY_BYTES);
    }
  }

  private static boolean isHardened(byte[] path, short indexOffset) {
    return (path[indexOffset] & (byte) 0x80) == (byte) 0x80;
  }
}
