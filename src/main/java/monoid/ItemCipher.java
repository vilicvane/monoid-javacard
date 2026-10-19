package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import monoididentity.CommunicationDataShareable;
import monoididentity.IdentityShareable;

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
    return new Result(
      safe,
      identity.encryptData(
        global(item.index),
        global(item.key),
        global(item.alias),
        item.secret,
        global(recipientPublicKey),
        new Source(new SafeData(item.data))
      )
    );
  }

  public CommunicationDataShareable decrypt(
    IdentityShareable identity,
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] senderPublicKey,
    SafeDataSource encryptedData
  ) {
    return identity.decryptData(
      global(index),
      global(key),
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

  static final class Result implements SafeDataSource {

    private final Safe safe;
    private final CommunicationDataShareable data;

    Result(Safe safe, CommunicationDataShareable data) {
      this.safe = safe;
      this.data = data;
    }

    @Override
    public short getLength() {
      safe.assertAccess();
      return data.getLength();
    }

    @Override
    public void read(short dataOffset, byte[] dest, short offset, short length) {
      safe.assertAccess();
      byte[] buffer = (byte[]) JCSystem.makeGlobalArray(
        JCSystem.ARRAY_TYPE_BYTE,
        Utils.min(length, (short) 64)
      );

      while (length > 0) {
        short copied = Utils.min(length, (short) buffer.length);
        data.read(dataOffset, buffer, (short) 0, copied);
        Util.arrayCopyNonAtomic(buffer, (short) 0, dest, offset, copied);
        dataOffset += copied;
        offset += copied;
        length -= copied;
      }
    }
  }
}
