package monoidotp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import monoidlib.CBORMap;

final class CommandPrepare extends Command {

  private final Object[] fields = { Text.time, Text.data, Text.signature, Text.indices };

  @Override
  protected void run() {
    OTPBatch batch = MonoidOTPApplet.takeBatch();
    CBORMap request = reader.map(fields);
    byte[] time = null;
    byte[] data = null;
    byte[] signature = null;

    if (request.key(Text.time)) {
      time = reader.bytes((short) 8);

      if (request.key(Text.data) || request.key(Text.signature)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      batch = new OTPBatch(null);
    } else {
      if (batch == null || batch.isPrepared()) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }

      data = request.requireKey(Text.data).bytesGlobal((short) 41);
      signature = request.requireKey(Text.signature).bytesGlobal((short) 64);
    }

    short count = request.requireKey(Text.indices).array();

    if (count <= 0 || count > Constants.MAX_ACCOUNTS) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    byte[] indices = new byte[(short) (count * Constants.INDEX_LENGTH)];

    for (short index = 0; index < count; index++) {
      short offset = (short) (index * Constants.INDEX_LENGTH);

      reader.bytes(indices, offset, Constants.INDEX_LENGTH);

      if (Util.getShort(indices, offset) != Constants.ACCOUNT_TYPE) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      for (short previous = 0; previous < offset; previous += Constants.INDEX_LENGTH) {
        if (Util.arrayCompare(indices, previous, indices, offset, Constants.INDEX_LENGTH) == 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
      }
    }

    // connect() borrows APDU scratch; all request fields are copied out before this call.
    MonoidOTPApplet.connect().revokeUserAuthentication();

    if (time != null) {
      batch.prepare(time, indices);
    } else {
      batch.prepare(data, signature, indices);
    }

    MonoidOTPApplet.setBatch(batch);

    writer.map((short) 0);
  }
}
