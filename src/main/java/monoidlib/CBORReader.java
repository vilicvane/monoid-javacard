package monoidlib;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/** Shared CBOR parsing over a contiguous buffer or logical chunks. */
public class CBORReader implements ByteSource {

  public static final byte PROFILE_MONOID = 0;
  public static final byte PROFILE_CTAP = 1;
  public static final short INTEGER_OUT_OF_RANGE = (short) 0x8000;

  private static final short OFFSET = 0;
  protected static final short END = 1;
  private static final short ARRAY_OFFSET = 0;
  private static final short MAP_LENGTH = 1;
  private static final short MAP_OFFSET = 2;
  private static final short SNAPSHOT_INDEX = 3;
  private static final short INITIAL_OFFSET = 4;
  private static final short INITIAL_MAP_LENGTH = 5;
  private static final short SNAPSHOT_LENGTH = 4;
  private static final short MAX_SNAPSHOTS = 8;

  // CTAP parser statuses; the Monoid profile maps these failures to SW_WRONG_DATA.
  private static final short INVALID_LENGTH = 0x03;
  private static final short UNEXPECTED_TYPE = 0x11;
  private static final short INVALID_CBOR = 0x12;
  private static final short MISSING_PARAMETER = 0x14;
  private static final short LIMIT_EXCEEDED = 0x15;

  protected final byte[] buffer;
  private final boolean strict;
  protected final short[] state = JCSystem.makeTransientShortArray(
    (short) 2,
    JCSystem.CLEAR_ON_DESELECT
  );
  private short[] navigation;
  private short[] snapshots;

  /** Creates a strict CTAP reader; its cursor and end occupy four transient bytes. */
  public CBORReader(byte[] buffer, short initialOffset, short length) {
    this(buffer, initialOffset, length, PROFILE_CTAP);
  }

  public CBORReader(byte[] buffer, short initialOffset, short length, byte profile) {
    this.buffer = buffer;
    strict = profile == PROFILE_CTAP;
    if (!strict) {
      navigation = JCSystem.makeTransientShortArray((short) 6, JCSystem.CLEAR_ON_DESELECT);
    }
    reset(initialOffset, length);
  }

  /** Chunk readers provide their bounds and ByteSource methods without assembling a buffer. */
  protected CBORReader() {
    this(null, (short) 0, (short) 0, PROFILE_MONOID);
  }

  public void reset(short initialOffset, short length) {
    state[END] = (short) (initialOffset + length);
    reset(initialOffset);
  }

  protected void reset(short offset) {
    state[OFFSET] = offset;
    if (navigation != null) {
      navigation[ARRAY_OFFSET] = -1;
      navigation[MAP_OFFSET] = -1;
      navigation[SNAPSHOT_INDEX] = 0;
      navigation[INITIAL_OFFSET] = offset;
      navigation[INITIAL_MAP_LENGTH] = navigation[MAP_LENGTH];
      if (snapshots != null) {
        saveSnapshot((short) 0);
      }
    }
  }

  protected short getLength() {
    return state[END];
  }

  /** Updates logical input bounds without changing the parser cursor or snapshots. */
  protected final void setLength(short length) {
    state[END] = length;
  }

  public short getOffset() {
    return state[OFFSET];
  }

  public void setOffset(short offset) {
    state[OFFSET] = offset;
  }

  public byte[] getBuffer() {
    return buffer;
  }

  @Override
  public byte[] getChunk(short offset) {
    return buffer;
  }

  @Override
  public short getChunkOffset(short offset) {
    return offset;
  }

  @Override
  public short getChunkLength(short offset) {
    return (short) (getLength() - offset);
  }

  public boolean atEnd() {
    return state[OFFSET] == getLength();
  }

  boolean isStrict() {
    return strict;
  }

  void invalid() {
    fail(INVALID_CBOR);
  }

  void missing() {
    fail(MISSING_PARAMETER);
  }

  private void fail(short reason) {
    ISOException.throwIt(strict ? reason : ISO7816.SW_WRONG_DATA);
  }

  private void assertLength(short length) {
    if (length < 0 || state[OFFSET] < 0 || state[OFFSET] > (short) (getLength() - length)) {
      invalid();
    }
  }

  private byte read(short offset) {
    return buffer != null ? buffer[offset] : getChunk(offset)[getChunkOffset(offset)];
  }

  private void copy(short offset, byte[] out, short outOffset, short length) {
    if (buffer != null) {
      Util.arrayCopyNonAtomic(buffer, offset, out, outOffset, length);
      return;
    }
    while (length > 0) {
      short chunkLength = getChunkLength(offset);
      if (chunkLength > length) {
        chunkLength = length;
      }
      Util.arrayCopyNonAtomic(
        getChunk(offset),
        getChunkOffset(offset),
        out,
        outOffset,
        chunkLength
      );
      offset += chunkLength;
      outOffset += chunkLength;
      length -= chunkLength;
    }
  }

  private boolean matches(short offset, byte[] value, short valueOffset, short length) {
    if (buffer != null) {
      return Util.arrayCompare(buffer, offset, value, valueOffset, length) == 0;
    }
    for (short index = 0; index < length; index++) {
      if (read((short) (offset + index)) != value[(short) (valueOffset + index)]) {
        return false;
      }
    }
    return true;
  }

  public boolean is(byte type) {
    assertLength((short) 1);
    return (read(state[OFFSET]) & CBOR.TYPE_MASK) == type;
  }

  public short integer() {
    boolean negative = is(CBOR.TYPE_NEGATIVE_INT);
    short value = argument(negative ? CBOR.TYPE_NEGATIVE_INT : CBOR.TYPE_UNSIGNED_INT);
    return value < 0 ? INTEGER_OUT_OF_RANGE : negative ? (short) (-value - 1) : value;
  }

  /** Copies into a persistent array and advances past the complete byte string. */
  public byte[] bytes() {
    return bytesLike(CBOR.TYPE_BYTES, (byte) 0);
  }

  /** Copies into a persistent array, advances past the byte string, and checks its length. */
  public byte[] bytes(short expectedLength) {
    byte[] value = bytes();
    assertExpectedLength((short) value.length, expectedLength);
    return value;
  }

  /** Copies into CLEAR_ON_DESELECT RAM, leaving the cursor at the content start. */
  public byte[] bytesTransient() {
    return bytesLike(CBOR.TYPE_BYTES, (byte) 1);
  }

  /** Copies into CLEAR_ON_DESELECT RAM, leaving the cursor at the content start. */
  public byte[] bytesTransient(short expectedLength) {
    byte[] value = bytesTransient();
    assertExpectedLength((short) value.length, expectedLength);
    return value;
  }

  /** Copies into a call-scoped global array, leaving the cursor at the content start. */
  public byte[] bytesGlobal() {
    return bytesLike(CBOR.TYPE_BYTES, (byte) 2);
  }

  /** Copies into a call-scoped global array, leaving the cursor at the content start. */
  public byte[] bytesGlobal(short expectedLength) {
    byte[] value = bytesGlobal();
    assertExpectedLength((short) value.length, expectedLength);
    return value;
  }

  /** Copies into the caller's array and advances past the complete byte string. */
  public short bytes(byte[] out, short outOffset) {
    return bytesLike(CBOR.TYPE_BYTES, out, outOffset);
  }

  /** Copies into the caller's array and advances past the complete byte string. */
  public short bytes(byte[] out) {
    return bytes(out, (short) 0);
  }

  /** Checks the length, copies into the caller's array, and advances past the byte string. */
  public void bytes(byte[] out, short outOffset, short expectedLength) {
    short start = bytesOffset();
    assertExpectedLength((short) (state[OFFSET] - start), expectedLength);
    copy(start, out, outOffset, expectedLength);
  }

  /** Reads the header, leaving the cursor at the content start for ByteSource access. */
  public short bytesLength() {
    return bytesLikeLength(CBOR.TYPE_BYTES);
  }

  /** Returns the content offset and advances past the complete byte string, without copying. */
  public short bytesOffset() {
    return bytesLikeOffset(CBOR.TYPE_BYTES);
  }

  /** Copies into a persistent array and advances past the complete text string. */
  public byte[] text() {
    return bytesLike(CBOR.TYPE_TEXT, (byte) 0);
  }

  /** Copies into CLEAR_ON_DESELECT RAM, leaving the cursor at the content start. */
  public byte[] textTransient() {
    return bytesLike(CBOR.TYPE_TEXT, (byte) 1);
  }

  /** Copies into the caller's array and advances past the complete text string. */
  public short text(byte[] out, short outOffset) {
    return bytesLike(CBOR.TYPE_TEXT, out, outOffset);
  }

  /** Copies into the caller's array and advances past the complete text string. */
  public short text(byte[] out) {
    return text(out, (short) 0);
  }

  /** Returns the content offset and advances past the complete text string, without copying. */
  public short textOffset() {
    return bytesLikeOffset(CBOR.TYPE_TEXT);
  }

  public boolean textMatches(byte[] value) {
    short start = textOffset();
    short length = (short) (state[OFFSET] - start);
    return value.length == length && matches(start, value, (short) 0, length);
  }

  private void assertExpectedLength(short length, short expected) {
    if (length != expected) {
      fail(INVALID_LENGTH);
    }
  }

  private short bytesLikeLength(byte type) {
    short length = metadata(type);
    assertLength(length);
    if (strict && type == CBOR.TYPE_TEXT) {
      assertText(length);
    }
    return length;
  }

  private short bytesLikeOffset(byte type) {
    short length = bytesLikeLength(type);
    short offset = state[OFFSET];
    state[OFFSET] += length;
    return offset;
  }

  private short bytesLike(byte type, byte[] out, short outOffset) {
    short length = bytesLikeLength(type);
    copy(state[OFFSET], out, outOffset, length);
    state[OFFSET] += length;
    return length;
  }

  private byte[] bytesLike(byte type, byte storage) {
    short length = bytesLikeLength(type);
    byte[] out = storage == 0
      ? new byte[length]
      : storage == 1
        ? JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT)
        : (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, length);
    copy(state[OFFSET], out, (short) 0, length);
    if (storage == 0) {
      state[OFFSET] += length;
    }
    return out;
  }

  public short array() {
    short length = itemsLength(CBOR.TYPE_ARRAY);
    if (navigation != null) {
      navigation[ARRAY_OFFSET] = state[OFFSET];
    }
    return length;
  }

  public short map() {
    short length = itemsLength(CBOR.TYPE_MAP);
    if (navigation != null) {
      navigation[MAP_LENGTH] = length;
      navigation[MAP_OFFSET] = state[OFFSET];
    }
    return length;
  }

  public CBORMap map(short[] keys) {
    return new CBORMap(this, keys);
  }

  public CBORMap map(Object[] keys) {
    return new CBORMap(this, keys);
  }

  /** Reads a text map key and returns its selected field index, or -1. */
  public short readKey(Object[] keys) {
    short length = bytesLikeLength(CBOR.TYPE_TEXT);
    short offset = state[OFFSET];
    state[OFFSET] += length;
    for (short index = 0; index < keys.length; index++) {
      byte[] key = (byte[]) keys[index];
      if (key.length == length && matches(offset, key, (short) 0, length)) {
        return index;
      }
    }
    return -1;
  }

  /** Reads an integer map key without folding an unsupported wide integer into a short. */
  public short readKey(short[] keys, boolean sequential) {
    boolean negative = is(CBOR.TYPE_NEGATIVE_INT);
    short value = argument(negative ? CBOR.TYPE_NEGATIVE_INT : CBOR.TYPE_UNSIGNED_INT);
    if (value < 0) {
      return -1;
    }
    return CBORMap.indexOf(keys, sequential, negative ? (short) (-value - 1) : value);
  }

  public boolean key(byte[] key, short offset, short length) {
    state[OFFSET] = navigation[MAP_OFFSET];
    for (short index = 0; navigation[MAP_LENGTH] < 0 || index < navigation[MAP_LENGTH]; index++) {
      assertLength((short) 1);
      if (read(state[OFFSET]) == CBOR.BREAK) {
        break;
      }
      short keyLength = bytesLikeLength(CBOR.TYPE_TEXT);
      boolean matched = keyLength == length && matches(state[OFFSET], key, offset, length);
      state[OFFSET] += keyLength;
      if (matched) {
        return true;
      }
      skip();
    }
    state[OFFSET] = navigation[MAP_OFFSET];
    return false;
  }

  public boolean key(byte[] key) {
    return key(key, (short) 0, (short) key.length);
  }

  public CBORReader requireKey(byte[] key, short offset, short length) {
    if (!key(key, offset, length)) {
      missing();
    }
    return this;
  }

  public CBORReader requireKey(byte[] key) {
    return requireKey(key, (short) 0, (short) key.length);
  }

  public boolean index(short index) {
    state[OFFSET] = navigation[ARRAY_OFFSET];
    for (short skipping = 0; skipping <= index; skipping++) {
      assertLength((short) 1);
      if (read(state[OFFSET]) == CBOR.BREAK) {
        break;
      }
      if (skipping == index) {
        return true;
      }
      skip();
    }
    state[OFFSET] = navigation[ARRAY_OFFSET];
    return false;
  }

  public boolean bool() {
    assertLength((short) 1);
    byte value = read(state[OFFSET]);
    if (strict) {
      state[OFFSET]++;
    }
    if (value != CBOR.FALSE && value != CBOR.TRUE) {
      fail(UNEXPECTED_TYPE);
    }
    if (!strict) {
      state[OFFSET]++;
    }
    return value == CBOR.TRUE;
  }

  public boolean boolFalse() {
    return boolValue(CBOR.FALSE);
  }

  public boolean boolTrue() {
    return boolValue(CBOR.TRUE);
  }

  private boolean boolValue(byte expected) {
    assertLength((short) 1);
    if (read(state[OFFSET]) != expected) {
      fail(UNEXPECTED_TYPE);
    }
    state[OFFSET]++;
    return expected == CBOR.TRUE;
  }

  public boolean br() {
    assertLength((short) 1);
    if (read(state[OFFSET]) != CBOR.BREAK) {
      return false;
    }
    state[OFFSET]++;
    return true;
  }

  public void skip() {
    skip((byte) 0);
  }

  /** Continues structural skipping at the caller's current container depth. */
  public void skip(byte depth) {
    if (strict && depth == 8) {
      fail(LIMIT_EXCEEDED);
    }
    assertLength((short) 1);
    byte type = (byte) (read(state[OFFSET]) & CBOR.TYPE_MASK);
    switch (type) {
      case CBOR.TYPE_BYTES:
      case CBOR.TYPE_TEXT:
        bytesLikeOffset(type);
        break;
      case CBOR.TYPE_ARRAY:
      case CBOR.TYPE_MAP: {
        short length = itemsLength(type);
        for (short index = 0; length < 0 || index < length; index++) {
          if (!strict && br()) {
            if (length < 0) {
              break;
            }
            invalid();
          }
          skip((byte) (depth + 1));
          if (type == CBOR.TYPE_MAP) {
            skip((byte) (depth + 1));
          }
        }
        break;
      }
      case CBOR.TYPE_UNSIGNED_INT:
      case CBOR.TYPE_NEGATIVE_INT:
        if (strict) {
          argument(type);
        } else {
          short metadata = (short) (read(state[OFFSET]) & CBOR.METADATA_MASK);
          if (metadata > 27) {
            invalid();
          }
          short length = metadata < 24 ? 1 : (short) (1 + (1 << (metadata & 3)));
          assertLength(length);
          state[OFFSET] += length;
        }
        break;
      case CBOR.TYPE_SIMPLE_FLOAT:
        skipSimple();
        break;
      default:
        invalid();
    }
  }

  private short itemsLength(byte type) {
    if (!strict && is(type) && (read(state[OFFSET]) & CBOR.METADATA_MASK) == 31) {
      state[OFFSET]++;
      return -1;
    }
    return metadata(type);
  }

  private short metadata(byte type) {
    short value = argument(type);
    if (value < 0) {
      invalid();
    }
    return value;
  }

  /** Decodes a shared CBOR argument; strict mode also enforces shortest encoding. */
  private short argument(byte type) {
    if (!is(type)) {
      fail(UNEXPECTED_TYPE);
    }
    short metadata = (short) (read(state[OFFSET]) & CBOR.METADATA_MASK);
    if (metadata < 24) {
      state[OFFSET]++;
      return metadata;
    }
    if (metadata > 27) {
      invalid();
    }
    short length = (short) (1 << (metadata & 3));
    if (!strict && length > 2) {
      invalid();
    }
    state[OFFSET]++;
    assertLength(length);
    short value;
    if (length == 1) {
      value = (short) (read(state[OFFSET]) & 0xFF);
      if (strict && value < 24) {
        invalid();
      }
      state[OFFSET]++;
      return value;
    }
    if (length == 2) {
      if (strict && read(state[OFFSET]) == 0) {
        invalid();
      }
      value = buffer != null
        ? Util.getShort(buffer, state[OFFSET])
        : (short) (((read(state[OFFSET]) & 0xFF) << 8) |
          (read((short) (state[OFFSET] + 1)) & 0xFF));
      if (!strict && value < 0) {
        invalid();
      }
      state[OFFSET] += 2;
      return value < 0 ? (short) -1 : value;
    }
    short leading = 0;
    for (short index = 0; index < (short) (length / 2); index++) {
      leading |= (short) (read((short) (state[OFFSET] + index)) & 0xFF);
    }
    if (leading == 0) {
      invalid();
    }
    state[OFFSET] += length;
    return -1;
  }

  private void skipSimple() {
    byte value = read(state[OFFSET]);
    if (!strict) {
      if (value != CBOR.FALSE && value != CBOR.TRUE && value != CBOR.BREAK) {
        invalid();
      }
      state[OFFSET]++;
      return;
    }
    short metadata = (short) (value & CBOR.METADATA_MASK);
    state[OFFSET]++;
    if (metadata < 24) {
      return;
    }
    if (metadata > 27) {
      invalid();
    }
    short length = (short) (1 << (metadata - 24));
    assertLength(length);
    if (metadata == 24 && (short) (read(state[OFFSET]) & 0xFF) < 32) {
      invalid();
    }
    state[OFFSET] += length;
  }

  private void assertText(short length) {
    short end = (short) (state[OFFSET] + length);
    for (short cursor = state[OFFSET]; cursor < end; ) {
      short first = (short) (read(cursor++) & 0xFF);
      if (first < 0x80) {
        continue;
      }
      short continuation;
      if (first >= 0xC2 && first <= 0xDF) {
        continuation = 1;
      } else if (first >= 0xE0 && first <= 0xEF) {
        continuation = 2;
      } else if (first >= 0xF0 && first <= 0xF4) {
        continuation = 3;
      } else {
        invalid();
        return;
      }
      if (cursor > (short) (end - continuation)) {
        invalid();
      }
      for (short index = 0; index < continuation; index++) {
        short value = (short) (read(cursor++) & 0xFF);
        if (
          value < 0x80 ||
          value > 0xBF ||
          (index == 0 &&
            ((first == 0xE0 && value < 0xA0) ||
              (first == 0xED && value > 0x9F) ||
              (first == 0xF0 && value < 0x90) ||
              (first == 0xF4 && value > 0x8F)))
        ) {
          invalid();
        }
      }
    }
  }

  public void snapshot() {
    requireSnapshots();
    navigation[SNAPSHOT_INDEX]++;
    saveSnapshot(navigation[SNAPSHOT_INDEX]);
  }

  public void resetSnapshot() {
    requireSnapshots();
    navigation[SNAPSHOT_INDEX] = 0;
    saveSnapshot((short) 0);
  }

  public void popSnapshot(boolean restore) {
    navigation[SNAPSHOT_INDEX]--;
    if (restore) {
      restore();
    }
  }

  public void popSnapshot() {
    popSnapshot(true);
  }

  public void restore() {
    requireSnapshots();
    short offset = (short) (navigation[SNAPSHOT_INDEX] * SNAPSHOT_LENGTH);
    state[OFFSET] = snapshots[offset];
    navigation[ARRAY_OFFSET] = snapshots[(short) (offset + 1)];
    navigation[MAP_LENGTH] = snapshots[(short) (offset + 2)];
    navigation[MAP_OFFSET] = snapshots[(short) (offset + 3)];
  }

  private void requireSnapshots() {
    if (snapshots == null) {
      snapshots = JCSystem.makeTransientShortArray(
        (short) (MAX_SNAPSHOTS * SNAPSHOT_LENGTH),
        JCSystem.CLEAR_ON_DESELECT
      );
      snapshots[0] = navigation[INITIAL_OFFSET];
      snapshots[1] = -1;
      snapshots[2] = navigation[INITIAL_MAP_LENGTH];
      snapshots[3] = navigation[INITIAL_OFFSET];
    }
  }

  private void saveSnapshot(short index) {
    short offset = (short) (index * SNAPSHOT_LENGTH);
    snapshots[offset] = state[OFFSET];
    snapshots[(short) (offset + 1)] = navigation[ARRAY_OFFSET];
    snapshots[(short) (offset + 2)] = navigation[MAP_LENGTH];
    snapshots[(short) (offset + 3)] = state[OFFSET];
  }
}
