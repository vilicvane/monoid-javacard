package monoid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class SafeData implements SafeDataSource {

  private final byte[] data;
  private final ByteSource source;
  private final short offset;
  private final short length;

  public SafeData(byte[] data) {
    this.data = data;
    source = null;
    offset = 0;
    length = (short) data.length;
  }

  public SafeData(ByteSource source, short offset, short length) {
    data = null;
    this.source = source;
    this.offset = offset;
    this.length = length;
  }

  public static SafeData fromReader(CBORReader reader) {
    short length = reader.bytesLength();
    return new SafeData(reader, reader.getOffset(), length);
  }

  @Override
  public short getLength() {
    return length;
  }

  @Override
  public void read(short dataOffset, byte[] buffer, short bufferOffset, short length) {
    if (dataOffset < 0 || length < 0 || dataOffset > (short) (this.length - length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    if (data != null) {
      Util.arrayCopyNonAtomic(data, dataOffset, buffer, bufferOffset, length);
      return;
    }

    dataOffset += offset;

    while (length > 0) {
      short chunkLength = Utils.min(length, source.getChunkLength(dataOffset));

      Util.arrayCopyNonAtomic(
        source.getChunk(dataOffset),
        source.getChunkOffset(dataOffset),
        buffer,
        bufferOffset,
        chunkLength
      );

      dataOffset += chunkLength;
      bufferOffset += chunkLength;
      length -= chunkLength;
    }
  }
}
