package monoid;

import javacard.security.CryptoException;
import monoidlib.Utils;

/** Monoid-001 HKDF-SHA512 derivation. Initialize LibHMACSha512 before use. */
public final class Monoid001Derivation extends KeyDerivation {

  // @formatter:off
  public static final byte[] NAME = {'m','o','n','o','i','d','-','0','0','1'};
  public static final byte[] MASTER_KEY_LABEL = {'M','o','n','o','i','d','-','0','0','1'};
  // @formatter:on

  public static final short MASTER_LENGTH = 64;
  private static final short KEY_LENGTH = 32;

  private static final byte DOMAIN_SECP256R1 = 0;
  private static final byte DOMAIN_ED25519 = 1;

  // KeyDerivation scopes cached results by owner, so each instance keeps one fixed domain.
  private final byte domain;

  private byte[] workspace;

  public Monoid001Derivation(byte[] curveName) {
    if (Utils.isEqual(WeierstrassCurve.SECP256r1, curveName)) {
      domain = DOMAIN_SECP256R1;
    } else if (Utils.isEqual(EdwardsCurve.ED25519, curveName)) {
      domain = DOMAIN_ED25519;
    } else {
      CurveException.throwIt(CurveException.REASON_UNSUPPORTED_CURVE);
      domain = DOMAIN_SECP256R1;
    }
  }

  @Override
  protected byte[] getMasterKeyLabel() {
    return MASTER_KEY_LABEL;
  }

  /** Derives a P-256 scalar or Ed25519 seed from a 64-byte HKDF PRK and opaque context. */
  @Override
  protected byte[] deriveKey(byte[] master, byte[] context) {
    if (workspace == null) {
      workspace = new byte[MASTER_LENGTH];
    }

    if (domain == DOMAIN_ED25519) {
      expand(master, context, (byte) 0);
      return Utils.duplicateAsPersistent(workspace, (short) 0, KEY_LENGTH);
    }

    for (short counter = 0; counter < 256; counter++) {
      expand(master, context, (byte) counter);

      if (
        !Utils.isZero(workspace, (short) 0, KEY_LENGTH) &&
        LibMath.compare(workspace, (short) 0, CurveSECP256r1.R, (short) 0, KEY_LENGTH) < 0
      ) {
        return Utils.duplicateAsPersistent(workspace, (short) 0, KEY_LENGTH);
      }
    }

    CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    return null;
  }

  private void expand(byte[] master, byte[] context, byte counter) {
    // HKDF-Expand's first block; deriveKey uses its first 32 bytes.
    LibHMACSha512.begin(master, (short) 0, MASTER_LENGTH);
    LibHMACSha512.update(MASTER_KEY_LABEL, (short) 0, (short) MASTER_KEY_LABEL.length);
    workspace[0] = domain;
    LibHMACSha512.update(workspace, (short) 0, (short) 1);
    LibHMACSha512.update(context, (short) 0, (short) context.length);
    workspace[0] = counter;
    workspace[1] = 1;
    LibHMACSha512.finish(workspace, (short) 0, (short) 2, workspace, (short) 0);
  }
}
