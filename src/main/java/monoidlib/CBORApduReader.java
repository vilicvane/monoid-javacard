package monoidlib;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Util;

/** APDU input storage and reception, independent of command framing and status words. */
public class CBORApduReader extends CBORReader {

  public static final short MAX_LENGTH = 8192;

  private static final short CHUNK_LENGTH = 256;

  private final short capacity;
  // Keep persistent chunks reachable until clear(), including after a card reset.
  private final Object[] chunks;

  /** Borrows complete short APDUs; larger requests allocate persistent 256B chunks on demand. */
  public CBORApduReader() {
    super();
    capacity = MAX_LENGTH;
    chunks = new Object[MAX_LENGTH / CHUNK_LENGTH];
  }

  /** Retains one persistent input buffer and the selected parsing profile across requests. */
  public CBORApduReader(short capacity, byte profile) {
    super(new byte[capacity], (short) 0, (short) 0, profile);
    this.capacity = capacity;
    chunks = null;
  }

  public short getReceivedLength() {
    return state[END];
  }

  public boolean hasChunks() {
    return chunks != null && chunks[0] != null;
  }

  /** Releases request chunks and length, retaining a fixed buffer and the parser cursor. */
  public void clear() {
    setLength((short) 0);
    if (chunks != null) {
      for (short index = 0; index < chunks.length; index++) {
        if (chunks[index] != null) {
          chunks[index] = null;
        }
      }
    }
  }

  /**
   * Appends one physical APDU after setIncomingAndReceive(). The caller chooses where
   * subsequent receiveBytes() blocks land and maps false to its protocol error.
   * Borrowing applies only to a complete first short frame; no global reference is retained.
   */
  public boolean receive(APDU apdu, short received, short receiveOffset, boolean borrowAPDU) {
    short length = apdu.getIncomingLength();
    short offset = getReceivedLength();
    if (length <= 0 || length > (short) (capacity - offset)) {
      return false;
    }

    short dataOffset = apdu.getOffsetCdata();
    if (
      borrowAPDU &&
      buffer == null &&
      offset == 0 &&
      chunks[0] == null &&
      dataOffset == ISO7816.OFFSET_CDATA &&
      received == length
    ) {
      setLength(length);
      return true;
    }

    byte[] input = apdu.getBuffer();
    short remaining = length;
    while (true) {
      if (received < 0 || received > remaining) {
        return false;
      }
      append(input, dataOffset, received);
      remaining -= received;
      if (remaining == 0) {
        return true;
      }
      dataOffset = receiveOffset;
      received = apdu.receiveBytes(dataOffset);
      if (received == 0) {
        return false;
      }
    }
  }

  private void append(byte[] input, short offset, short length) {
    short received = state[END];
    if (buffer != null) {
      Util.arrayCopyNonAtomic(input, offset, buffer, received, length);
      setLength((short) (received + length));
      return;
    }

    while (length > 0) {
      short chunkIndex = (short) (received / CHUNK_LENGTH);
      short chunkOffset = (short) (received % CHUNK_LENGTH);
      short chunkLength = (short) (CHUNK_LENGTH - chunkOffset);
      if (chunkLength > length) {
        chunkLength = length;
      }
      byte[] chunk = (byte[]) chunks[chunkIndex];
      if (chunk == null) {
        chunk = new byte[CHUNK_LENGTH];
        chunks[chunkIndex] = chunk;
      }
      Util.arrayCopyNonAtomic(input, offset, chunk, chunkOffset, chunkLength);
      received += chunkLength;
      setLength(received);
      offset += chunkLength;
      length -= chunkLength;
    }
  }

  @Override
  public byte[] getChunk(short offset) {
    if (buffer != null) {
      return buffer;
    }
    return chunks[0] != null
      ? (byte[]) chunks[(short) (offset / CHUNK_LENGTH)]
      : APDU.getCurrentAPDUBuffer();
  }

  @Override
  public short getChunkOffset(short offset) {
    if (buffer != null) {
      return offset;
    }
    return chunks[0] != null
      ? (short) (offset % CHUNK_LENGTH)
      : (short) (ISO7816.OFFSET_CDATA + offset);
  }

  @Override
  public short getChunkLength(short offset) {
    short remaining = (short) (getLength() - offset);
    if (buffer != null || chunks[0] == null) {
      return remaining;
    }
    short chunkLength = (short) (CHUNK_LENGTH - (short) (offset % CHUNK_LENGTH));
    return chunkLength < remaining ? chunkLength : remaining;
  }
}
