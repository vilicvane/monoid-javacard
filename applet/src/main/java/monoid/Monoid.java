package monoid;

import javacard.framework.Shareable;

public interface Monoid extends Shareable {
  public static final byte KEY_TYPE_ECDSA_SECP256K1 = 1;
  public static final byte KEY_TYPE_ED25519 = 2;

  short getId();
}
