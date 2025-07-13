package monoidkeystore;

import javacard.framework.*;
import javacard.security.*;

public interface MonoidKeystore extends Shareable {
  public void verifyPIN(byte[] buffer, short offset, byte length);

  public void updatePIN(byte[] buffer, short offset, byte length);

  public byte[] getKeyPairTypes();

  public KeyPair[] getKeyPairs();

  public short getKeyPairsLength();

  public void pushKeyPair(byte type, KeyPair pair);

  public void removeKeyPair(KeyPair pair);
}
