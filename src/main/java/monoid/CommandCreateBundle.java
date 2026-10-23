package monoid;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import monoidlib.CBORApduReader;
import monoidlib.CBORReader;
import monoidlib.CBORResponse;
import monoidlib.CBORWriter;
import monoidlib.Utils;

public final class CommandCreateBundle extends Command implements CBORResponse {

  private static final short PUBLIC_KEY_LENGTH = 65;
  private static final short CHUNK_LENGTH = 256;

  private final Object[] references = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final short[] state = JCSystem.makeTransientShortArray(
    (short) 3,
    JCSystem.CLEAR_ON_DESELECT
  );

  @Override
  protected void run() {
    requireAuth(AUTH_SECRET);

    reader.map();

    short count = reader.requireKey(Text.publicKeys).array();

    if (count < 1 || count > CBORApduReader.MAX_LENGTH / (PUBLIC_KEY_LENGTH + 2)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Reserve the response window before creating and publishing the Bundle.
    // Each unit contains at most a byte-string header and one data chunk.
    writer.start(this, (short) (CHUNK_LENGTH + 3));

    byte[] publicKeys = new byte[(short) (count * PUBLIC_KEY_LENGTH)];

    for (short index = 0; index < count; index++) {
      short offset = reader.getOffset();

      if (reader.bytesLength() != PUBLIC_KEY_LENGTH) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      // Work around CAP converter lookup failures by referencing setOffset's declaring class.
      ((CBORReader) reader).setOffset(offset);
      reader.bytes(publicKeys, (short) (index * PUBLIC_KEY_LENGTH));
    }

    SafeDataSource data = MonoidApplet.safe.createBundle(publicKeys);
    short length = data.getLength();

    references[0] = data;
    state[0] = length;
    state[1] = (short) (length / count);
    state[2] = 0;

    writer.map((short) 2);
    {
      writer.text(Text.bundle);
      writer.bytes(MonoidApplet.safe.getBundle());

      writer.text(Text.data);
      writer.array(count);
    }
  }

  @Override
  public boolean writeNext(CBORWriter writer) {
    if (state[2] >= state[0]) {
      return false;
    }

    short packetOffset = (short) (state[2] % state[1]);

    if (packetOffset == 0) {
      writer.bytesLength(state[1]);
    }

    byte[] buffer = APDU.getCurrentAPDUBuffer();
    short length = Utils.min(
      (short) (state[1] - packetOffset),
      Utils.min(CHUNK_LENGTH, (short) buffer.length)
    );

    ((SafeDataSource) references[0]).read(state[2], buffer, (short) 0, length);
    writer.rawBytes(buffer, (short) 0, length);

    state[2] += length;

    return state[2] < state[0];
  }

  @Override
  public void reset() {
    references[0] = null;

    for (short index = 0; index < state.length; index++) {
      state[index] = 0;
    }
  }
}
