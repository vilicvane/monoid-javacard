package monoidlib;

/** Monoid's permissive CBOR profile over a complete byte array. */
public class CBORBufferReader extends CBORReader {

  public CBORBufferReader(byte[] buffer) {
    super(buffer, (short) 0, (short) buffer.length, PROFILE_MONOID);
  }
}
