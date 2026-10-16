package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;

public final class LibBIP32 {

  // @formatter:off
  public static final byte[] NAME = {'b','i','p','3','2'};
  public static final byte[] MASTER_KEY_LABEL = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
  // @formatter:on

  public static final byte COMPONENT_LENGTH = 32;
  public static final byte PATH_SEGMENT_LENGTH = 4;

  public static byte[] derive(WeierstrassCurve curve, byte[] privateKeyAndChainCode, byte[] path) {
    if (!(curve instanceof CurveSECP256k1)) {
      CurveException.throwIt(CurveException.REASON_UNSUPPORTED_CURVE);
      return null;
    }

    privateKeyAndChainCode = Utils.duplicateAsTransientDeselect(privateKeyAndChainCode);

    if (path.length == 0) {
      return privateKeyAndChainCode;
    }

    byte[] data = JCSystem.makeTransientByteArray(
      (short) (1 + COMPONENT_LENGTH + PATH_SEGMENT_LENGTH),
      JCSystem.CLEAR_ON_DESELECT
    );
    byte[] currentPrivateKeyAndChainCode = JCSystem.makeTransientByteArray(
      (short) privateKeyAndChainCode.length,
      JCSystem.CLEAR_ON_DESELECT
    );
    byte[] block = JCSystem.makeTransientByteArray(
      LibHMACSha512.BLOCK_BYTES,
      JCSystem.CLEAR_ON_DESELECT
    );

    short pathOffset = 0;

    while (pathOffset < path.length) {
      pathOffset = deriveChildKeyInPlace(
        curve,
        privateKeyAndChainCode,
        path,
        pathOffset,
        data,
        currentPrivateKeyAndChainCode,
        block
      );
    }

    return privateKeyAndChainCode;
  }

  private static short deriveChildKeyInPlace(
    WeierstrassCurve curve,
    byte[] privateKeyAndChainCode,
    byte[] path,
    short pathSegmentOffset,
    byte[] data,
    byte[] currentPrivateKeyAndChainCode,
    byte[] block
  ) {
    short dataOffset = 0;

    Util.arrayCopyNonAtomic(
      privateKeyAndChainCode,
      (short) 0,
      currentPrivateKeyAndChainCode,
      (short) 0,
      (short) privateKeyAndChainCode.length
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
      (short) 0,
      block
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
