package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;

public final class LibBIP32 {

  public static final byte COMPONENT_LENGTH = 32;
  public static final byte PATH_SEGMENT_LENGTH = 4;

  public static byte[] derive(Curve curve, byte[] privateKeyAndChainCode, byte[] path) {
    privateKeyAndChainCode = Utils.duplicateAsTransientDeselect(privateKeyAndChainCode);

    short pathOffset = 0;

    while (pathOffset < path.length) {
      pathOffset = deriveChildKeyInPlace(curve, privateKeyAndChainCode, path, pathOffset);
    }

    return privateKeyAndChainCode;
  }

  private static short deriveChildKeyInPlace(
    Curve curve,
    byte[] privateKeyAndChainCode,
    byte[] path,
    short pathSegmentOffset
  ) {
    byte[] data = JCSystem.makeTransientByteArray(
      (short) (1 + COMPONENT_LENGTH + PATH_SEGMENT_LENGTH),
      JCSystem.CLEAR_ON_DESELECT
    );
    short dataOffset = 0;

    byte[] currentPrivateKeyAndChainCode = Utils.duplicateAsTransientDeselect(
      privateKeyAndChainCode
    );

    if (isHardened(path, pathSegmentOffset)) {
      // 0x00 || parent private key

      data[dataOffset++] = 0;
      dataOffset = Util.arrayCopyNonAtomic(
        currentPrivateKeyAndChainCode,
        (short) 0,
        data,
        dataOffset,
        COMPONENT_LENGTH
      );
    } else {
      // compression flag byte || parent public key

      ECPrivateKey privateKey = curve.getSharedPrivateKey(currentPrivateKeyAndChainCode, (short) 0);

      dataOffset += curve.derivePublicKey(privateKey, data, dataOffset);
    }

    dataOffset = Util.arrayCopyNonAtomic(path, pathSegmentOffset, data, dataOffset, (short) 4);

    // left 32 bytes for private key & right 32 bytes as chain code
    LibHMACSha512.digest(
      currentPrivateKeyAndChainCode,
      COMPONENT_LENGTH,
      COMPONENT_LENGTH,
      data,
      (short) 0,
      (short) data.length,
      privateKeyAndChainCode,
      (short) 0
    );

    if (
      LibMath.add(
          privateKeyAndChainCode,
          (short) 0,
          currentPrivateKeyAndChainCode,
          (short) 0,
          privateKeyAndChainCode,
          (short) 0,
          COMPONENT_LENGTH
        ) !=
        0 ||
      LibMath.compare(
        privateKeyAndChainCode,
        (short) 0,
        curve.getR(),
        (short) 0,
        COMPONENT_LENGTH
      ) >
      0
    ) {
      LibMath.sub(
        privateKeyAndChainCode,
        (short) 0,
        curve.getR(),
        (short) 0,
        privateKeyAndChainCode,
        (short) 0,
        COMPONENT_LENGTH
      );
    }

    return (short) (pathSegmentOffset + PATH_SEGMENT_LENGTH);
  }

  private static boolean isHardened(byte[] path, short indexOffset) {
    return (path[indexOffset] & (byte) 0x80) == (byte) 0x80;
  }
}
