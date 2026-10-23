package monoid;

import javacard.framework.APDU;
import javacard.framework.JCSystem;
import monoidlib.CBORApduWriter;
import monoidlib.CBORResponse;
import monoidlib.CBORWriter;

public class SafeDataResponse implements CBORResponse {

  private static final short CHUNK_LENGTH = 256;

  private final Object[] references = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final short[] state = JCSystem.makeTransientShortArray(
    (short) 2,
    JCSystem.CLEAR_ON_DESELECT
  );

  public short start(CBORApduWriter writer, SafeDataSource data, short prefixLength) {
    short length = data.getLength();
    short headerLength = (short) (prefixLength + CBORWriter.metadataLength(length));
    short capacity = Utils.min(CHUNK_LENGTH, (short) APDU.getCurrentAPDUBuffer().length);
    boolean streamed = length > (short) (capacity - headerLength);

    if (streamed) {
      writer.start(this, headerLength > CHUNK_LENGTH ? headerLength : CHUNK_LENGTH);
    } else {
      writer.reset();
    }

    references[0] = data;
    state[0] = length;
    state[1] = streamed ? (short) 0 : -1;

    return length;
  }

  public void writeData(CBORWriter writer) {
    if (state[1] >= 0) {
      return;
    }

    try {
      if (state[0] > 0) {
        byte[] buffer = APDU.getCurrentAPDUBuffer();
        short offset = writer.getLength();

        ((SafeDataSource) references[0]).read((short) 0, buffer, offset, state[0]);
        writer.rawBytes(buffer, offset, state[0]);
      }
    } finally {
      reset();
    }
  }

  @Override
  public boolean writeNext(CBORWriter writer) {
    short remaining = (short) (state[0] - state[1]);

    if (remaining == 0) {
      return false;
    }

    byte[] buffer = APDU.getCurrentAPDUBuffer();
    short length = Utils.min(remaining, Utils.min(CHUNK_LENGTH, (short) buffer.length));

    ((SafeDataSource) references[0]).read(state[1], buffer, (short) 0, length);
    writer.rawBytes(buffer, (short) 0, length);

    state[1] += length;

    return state[1] < state[0];
  }

  @Override
  public void reset() {
    references[0] = null;
    state[0] = 0;
    state[1] = 0;
  }
}
