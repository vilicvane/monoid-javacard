package monoidotp;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import monoid.Monoid;
import monoid.SafeItemShareable;
import monoididentity.IdentityShareable;
import monoidlib.CBORWriter;
import monoidlib.Utils;

final class OTPBatch {

  private final byte[] challenge;
  private byte[] time;
  private byte[] indices;

  OTPBatch(byte[] challenge) {
    this.challenge = challenge;
  }

  boolean isPrepared() {
    return time != null;
  }

  void prepare(byte[] data, byte[] signature, byte[] indices) {
    IdentityShareable identity = requireIdentity();

    // The reader provides data and signature as call-scoped global arrays.
    identity.verifyAuthorityTime(data, signature, Utils.duplicateAsGlobal(challenge));

    this.time = new byte[8];
    Util.arrayCopyNonAtomic(data, (short) 1, time, (short) 0, (short) time.length);
    this.indices = indices;
  }

  void prepare(byte[] time, byte[] indices) {
    if (requireIdentity().getAuthority() != null) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    this.time = time;
    this.indices = indices;
  }

  private static IdentityShareable requireIdentity() {
    AID aid = JCSystem.lookupAID(
      Constants.MONOID_IDENTITY_AID,
      (short) 0,
      (byte) Constants.MONOID_IDENTITY_AID.length
    );

    if (aid == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    IdentityShareable identity = (IdentityShareable) JCSystem.getAppletShareableInterfaceObject(
      aid,
      (byte) 0
    );

    if (identity == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    return identity;
  }

  void calculate(Monoid monoid, CBORWriter writer) {
    byte[] index = Utils.makeGlobalByteArray(Constants.INDEX_LENGTH);
    byte[] keyIndex = Utils.makeGlobalByteArray(Constants.INDEX_LENGTH);
    byte[] counter = Utils.makeGlobalByteArray((short) 8);
    byte[] hash = Utils.makeGlobalByteArray((short) 64);
    byte[] code = new byte[8];
    byte[] value = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT);

    writer.map((short) 2);
    writer.text(Text.time);
    writer.bytes(time);
    writer.text(Text.items);
    writer.array((short) (indices.length / Constants.INDEX_LENGTH));

    for (short offset = 0; offset < indices.length; offset += Constants.INDEX_LENGTH) {
      Util.arrayCopyNonAtomic(indices, offset, index, (short) 0, Constants.INDEX_LENGTH);
      SafeItemShareable item = monoid.get(index);

      if (item == null) {
        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
      }

      byte[] configuration = item.getMetadata();

      if (configuration == null || configuration.length != 5 || configuration[0] != 1) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      byte algorithm = configuration[1];
      byte digits = configuration[2];
      short period = Util.getShort(configuration, (short) 3);

      if (
        (algorithm != Monoid.HMAC_SHA1 &&
          algorithm != Monoid.HMAC_SHA256 &&
          algorithm != Monoid.HMAC_SHA512) ||
        (digits != 6 && digits != 8) ||
        period <= 0
      ) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      if (
        monoid.readData(index, configuration, keyIndex, (short) 0, Constants.INDEX_LENGTH) !=
        Constants.INDEX_LENGTH
      ) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      LibTOTP.counter(time, period, counter, (short) 0);

      writer.map((short) 3);
      writer.text(Text.index);
      writer.bytes(index);
      writer.text(Text.period);
      writer.integer(period);
      writer.text(Text.codes);
      writer.array(Constants.BATCH_SIZE);

      for (short window = 0; window < Constants.BATCH_SIZE; window++) {
        short length = monoid.hmac(
          algorithm,
          keyIndex,
          (short) 0,
          counter,
          (short) 0,
          (short) 8,
          hash,
          (short) 0
        );
        LibTOTP.truncate(hash, length, digits, code, value);
        writer.text(code, (short) 0, digits);

        if (window != Constants.BATCH_SIZE - 1) {
          LibTOTP.increment(counter, (short) 0);
        }
      }
    }
  }
}
