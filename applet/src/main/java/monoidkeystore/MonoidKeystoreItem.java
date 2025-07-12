package monoidkeystore;

import javacard.security.*;

public final class MonoidKeystoreItem {
  public final byte type;
  public final KeyPair pair;

  public MonoidKeystoreItem(byte type, KeyPair pair) {
    this.type = type;
    this.pair = pair;
  }
}
