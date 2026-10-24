package monoid;

import monoididentity.CommunicationDataShareable;
import monoididentity.IdentityShareable;
import monoidlib.Utils;

/** Moves item data across the Identity firewall without exposing communication keys. */
public class ItemCipher {

  public static final short SECRET_LENGTH = 2;

  private final Safe safe;

  public ItemCipher(Safe safe) {
    this.safe = safe;
  }

  public SafeDataSource encrypt(
    IdentityShareable identity,
    SafeItem item,
    byte[] recipientPublicKey
  ) {
    return new SafeIdentityData(
      safe,
      identity.encryptData(
        global(item.index),
        global(item.metadata),
        global(item.alias),
        item.getSecretValue(),
        global(recipientPublicKey),
        new Source(new SafeData(item.getStoredData()))
      )
    );
  }

  public CommunicationDataShareable decrypt(
    IdentityShareable identity,
    byte[] index,
    byte[] metadata,
    byte[] alias,
    byte[] senderPublicKey,
    SafeDataSource encryptedData
  ) {
    return identity.decryptData(
      global(index),
      global(metadata),
      global(alias),
      global(senderPublicKey),
      new Source(encryptedData)
    );
  }

  private static byte[] global(byte[] value) {
    return value == null ? null : Utils.duplicateAsGlobal(value);
  }

  private static final class Source implements CommunicationDataShareable {

    private final SafeDataSource data;

    Source(SafeDataSource data) {
      this.data = data;
    }

    @Override
    public short getLength() {
      return data.getLength();
    }

    @Override
    public void read(short dataOffset, byte[] buffer, short offset, short length) {
      data.read(dataOffset, buffer, offset, length);
    }
  }
}
