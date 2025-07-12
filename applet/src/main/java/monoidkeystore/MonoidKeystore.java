package monoidkeystore;

import javacard.framework.*;

public interface MonoidKeystore extends Shareable {
  public void verifyPIN(byte[] buffer, short offset, byte length);

  public void updatePIN(byte[] buffer, short offset, byte length);

  public MonoidKeystoreItem[] getItems();

  public short getItemsLength();

  public void setItemsLength(short length);

  public void extendItems();
}
