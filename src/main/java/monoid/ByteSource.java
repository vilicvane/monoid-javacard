package monoid;

/** Read-only access to logical bytes that may span multiple arrays. */
public interface ByteSource {
  /** Returns the array containing a valid logical byte offset. */
  byte[] getChunk(short offset);

  /** Maps a valid logical byte offset to its position in getChunk(offset). */
  short getChunkOffset(short offset);

  /** Returns the available bytes from offset to the end of that chunk's data. */
  short getChunkLength(short offset);
}
