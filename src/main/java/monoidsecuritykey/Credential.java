package monoidsecuritykey;

import static monoidsecuritykey.Constants.CREDENTIAL_TYPE;
import static monoidsecuritykey.Constants.KEY_DISPLAY_NAME;
import static monoidsecuritykey.Constants.KEY_ID;
import static monoidsecuritykey.Constants.KEY_NAME;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import monoid.Monoid;
import monoid.SafeDataShareable;
import monoid.SafeItemShareable;
import monoidlib.CBORBufferWriter;
import monoidlib.CBORReader;
import monoidlib.CBORWriter;
import monoidlib.Utils;

final class Credential implements SafeDataShareable {

  static final short READ_BUFFER_LENGTH = 320;
  private static final short REQUIRED_FIELDS = 0x039F;
  private static final short STATE_LENGTH = 12;
  private static final short LENGTH = 0;
  private static final short ID = 1;
  private static final short RP_HASH = 2;
  private static final short USER_ID = 3;
  private static final short USER_ID_LENGTH = 4;
  private static final short USER_NAME = 5;
  private static final short USER_NAME_LENGTH = 6;
  private static final short USER_DISPLAY_NAME = 7;
  private static final short USER_DISPLAY_NAME_LENGTH = 8;
  private static final short PUBLIC_KEY = 9;
  private static final short RESIDENT = 10;
  private static final short SCOPE = 11;

  // One private record owns every field. Neither APDU scratch nor a foreign array is retained.
  private final byte[] data;
  private final short[] state;
  private final byte[] stateSnapshot;
  private final CBORReader reader;
  private final byte[] label = new byte[19];
  private CBORBufferWriter writer;

  private Credential(short capacity) {
    this(capacity, false);
  }

  private Credential(short capacity, boolean cached) {
    data = new byte[capacity];
    state = JCSystem.makeTransientShortArray(STATE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    stateSnapshot = cached ? new byte[STATE_LENGTH * 2] : null;
    reader = new CBORReader(data, (short) 0, capacity);
  }

  static Credential cached() {
    return new Credential(READ_BUFFER_LENGTH, true);
  }

  Credential(
    byte[] id,
    byte[] rpHash,
    byte[] scope,
    byte[] rpId,
    byte[] userId,
    byte[] userName,
    byte[] userDisplayName,
    boolean resident,
    byte[] publicKey
  ) {
    this(
      id,
      rpHash,
      scope,
      new CredentialInput(rpId, userId, userName, userDisplayName),
      resident,
      publicKey
    );
  }

  private Credential(
    byte[] id,
    byte[] rpHash,
    byte[] scope,
    CredentialInput input,
    boolean resident,
    byte[] publicKey
  ) {
    this(encodedLength(id, rpHash, scope, input));
    encode(id, rpHash, scope, input, resident, publicKey);
  }

  static Credential create(
    byte[] id,
    byte[] rpHash,
    byte[] scope,
    byte[] rpId,
    byte[] userId,
    byte[] userName,
    byte[] userDisplayName,
    boolean resident,
    byte[] publicKey,
    Credential reusable
  ) {
    return create(
      id,
      rpHash,
      scope,
      new CredentialInput(rpId, userId, userName, userDisplayName),
      resident,
      publicKey,
      reusable
    );
  }

  static Credential create(
    byte[] id,
    byte[] rpHash,
    byte[] scope,
    CredentialInput input,
    boolean resident,
    byte[] publicKey,
    Credential reusable
  ) {
    Credential credential = workspace(encodedLength(id, rpHash, scope, input), reusable);
    credential.encode(id, rpHash, scope, input, resident, publicKey);
    return credential;
  }

  private void encode(
    byte[] id,
    byte[] rpHash,
    byte[] scope,
    CredentialInput input,
    boolean resident,
    byte[] publicKey
  ) {
    if (writer == null) {
      writer = new CBORBufferWriter(data, (short) 0, CTAP.LIMIT_EXCEEDED);
    } else {
      writer.reset((short) 0);
    }
    state[USER_NAME] = 0;
    state[USER_NAME_LENGTH] = 0;
    state[USER_DISPLAY_NAME] = 0;
    state[USER_DISPLAY_NAME_LENGTH] = 0;
    writer.map(
      (short) (8 +
        (input.length(CredentialInput.USER_NAME) < 0 ? 0 : 1) +
        (input.length(CredentialInput.USER_DISPLAY_NAME) < 0 ? 0 : 1))
    );
    writer.integer((short) 1);
    writer.integer((short) 1);
    writer.integer((short) 2);
    writer.bytes(id);
    state[ID] = (short) (writer.getLength() - id.length);
    writer.integer((short) 3);
    writer.bytes(rpHash);
    state[RP_HASH] = (short) (writer.getLength() - rpHash.length);
    writer.integer((short) 4);
    input.write(writer, CredentialInput.RP_ID);
    writer.integer((short) 5);
    input.write(writer, CredentialInput.USER_ID);
    state[USER_ID_LENGTH] = input.length(CredentialInput.USER_ID);
    state[USER_ID] = (short) (writer.getLength() - state[USER_ID_LENGTH]);
    if (input.length(CredentialInput.USER_NAME) >= 0) {
      writer.integer((short) 6);
      input.write(writer, CredentialInput.USER_NAME);
      state[USER_NAME_LENGTH] = input.length(CredentialInput.USER_NAME);
      state[USER_NAME] = (short) (writer.getLength() - state[USER_NAME_LENGTH]);
    }
    if (input.length(CredentialInput.USER_DISPLAY_NAME) >= 0) {
      writer.integer((short) 7);
      input.write(writer, CredentialInput.USER_DISPLAY_NAME);
      state[USER_DISPLAY_NAME_LENGTH] = input.length(CredentialInput.USER_DISPLAY_NAME);
      state[USER_DISPLAY_NAME] = (short) (writer.getLength() - state[USER_DISPLAY_NAME_LENGTH]);
    }
    writer.integer((short) 8);
    writer.bool(resident);
    state[RESIDENT] = resident ? Constants.SAFE_TRUE : Constants.SAFE_FALSE;
    writer.integer((short) 9);
    // A generated point may be in the larger APDU scratch buffer.
    writer.bytes(publicKey, (short) 0, (short) 65);
    state[PUBLIC_KEY] = (short) (writer.getLength() - 65);

    writer.integer((short) 10);
    writer.bytes(scope);
    state[SCOPE] = (short) (writer.getLength() - scope.length);
    state[LENGTH] = writer.getLength();
    updateLabel();
  }

  static Credential read(
    SafeItemShareable item,
    SafeDataShareable source,
    short length,
    Credential reusable
  ) {
    Credential credential = workspace(length, reusable);
    // The request is already private, and response encoding has not started.
    credential.load(item, source, length, APDU.getCurrentAPDUBuffer());
    return credential;
  }

  static Credential read(byte[] buffer, short offset, short length, Credential reusable) {
    Credential credential = workspace(length, reusable);
    Util.arrayCopyNonAtomic(buffer, offset, credential.data, (short) 0, length);
    credential.parse(length);
    return credential;
  }

  static Credential read(SafeDataShareable source, short length, Credential reusable) {
    Credential credential = workspace(length, reusable);
    credential.load(source, length, APDU.getCurrentAPDUBuffer());
    return credential;
  }

  private static Credential workspace(short length, Credential reusable) {
    return reusable == null || reusable.data.length < length
      ? new Credential(length <= READ_BUFFER_LENGTH ? READ_BUFFER_LENGTH : length)
      : reusable;
  }

  static Credential read(SafeItemShareable item, byte[] window) {
    SafeDataShareable source = item.getData();
    short length = source.getLength();
    Credential credential = new Credential(length);
    credential.load(item, source, length, window);
    return credential;
  }

  private void load(SafeItemShareable item, SafeDataShareable source, short length, byte[] window) {
    load(source, length, window);
    byte[] index = item.getIndex();
    if (index.length != 10) {
      ISOException.throwIt(CTAP.OTHER);
    }
    assertMetadata(index, (short) 0, item.getKey());
  }

  private void load(SafeDataShareable source, short length, byte[] window) {
    for (short offset = 0; offset < length; ) {
      short count = (short) (length - offset);
      if (count > window.length) {
        count = (short) window.length;
      }
      source.read(offset, window, (short) 0, count);
      Util.arrayCopyNonAtomic(window, (short) 0, data, offset, count);
      offset += count;
    }

    parse(length);
  }

  private void parse(short length) {
    reader.reset((short) 0, length);
    state[USER_NAME] = 0;
    state[USER_NAME_LENGTH] = 0;
    state[USER_DISPLAY_NAME] = 0;
    state[USER_DISPLAY_NAME_LENGTH] = 0;
    short count = reader.map();
    short seen = 0;
    // Stored records are flat maps. Read each value once, still accepting any field order.
    for (short index = 0; index < count; index++) {
      short field = reader.integer();
      if (field >= 1 && field <= 10) {
        short bit = (short) (1 << (field - 1));
        if ((seen & bit) != 0) {
          ISOException.throwIt(CTAP.INVALID_CBOR);
        }
        seen |= bit;
      }
      switch (field) {
        case 1:
          if (reader.integer() != 1) {
            ISOException.throwIt(CTAP.OTHER);
          }
          break;
        case 2:
          state[ID] = fixedBytes(reader, (short) 32);
          break;
        case 3:
          state[RP_HASH] = fixedBytes(reader, (short) 32);
          break;
        case 4:
          reader.textOffset();
          break;
        case 5:
          state[USER_ID] = reader.bytesOffset();
          state[USER_ID_LENGTH] = (short) (reader.getOffset() - state[USER_ID]);
          break;
        case 6:
          state[USER_NAME] = reader.textOffset();
          state[USER_NAME_LENGTH] = (short) (reader.getOffset() - state[USER_NAME]);
          break;
        case 7:
          state[USER_DISPLAY_NAME] = reader.textOffset();
          state[USER_DISPLAY_NAME_LENGTH] = (short) (reader.getOffset() - state[USER_DISPLAY_NAME]);
          break;
        case 8:
          state[RESIDENT] = reader.bool() ? Constants.SAFE_TRUE : Constants.SAFE_FALSE;
          break;
        case 9:
          state[PUBLIC_KEY] = fixedBytes(reader, (short) 65);
          break;
        case 10:
          state[SCOPE] = fixedBytes(reader, (short) 32);
          break;
        default:
          reader.skip();
      }
    }
    if (!reader.atEnd()) {
      ISOException.throwIt(CTAP.OTHER);
    }
    if ((seen & REQUIRED_FIELDS) != REQUIRED_FIELDS) {
      ISOException.throwIt(CTAP.MISSING_PARAMETER);
    }
    state[LENGTH] = length;
    updateLabel();
  }

  void assertMetadata(byte[] index, short offset, byte[] key) {
    if (!matchesIndex(index, offset) || key == null || !matchesKey(key)) {
      ISOException.throwIt(CTAP.OTHER);
    }
  }

  void saveState(byte[] window) {
    for (short index = 0; index < STATE_LENGTH; index++) {
      Util.setShort(window, (short) (index * 2), state[index]);
    }
    // Publish validated offsets with one persistent copy before the store publishes its source.
    Util.arrayCopyNonAtomic(
      window,
      (short) 0,
      stateSnapshot,
      (short) 0,
      (short) (STATE_LENGTH * 2)
    );
  }

  void restoreState() {
    if (state[LENGTH] == 0) {
      for (short index = 0; index < STATE_LENGTH; index++) {
        state[index] = Util.getShort(stateSnapshot, (short) (index * 2));
      }
    }
  }

  boolean matchesIndex(byte[] index, short offset) {
    return (
      Util.getShort(index, offset) == CREDENTIAL_TYPE &&
      Util.arrayCompare(index, (short) (offset + 2), data, state[ID], (short) 8) == 0
    );
  }

  private static short fixedBytes(CBORReader reader, short length) {
    short offset = reader.bytesOffset();
    if ((short) (reader.getOffset() - offset) != length) {
      ISOException.throwIt(CTAP.INVALID_LENGTH);
    }
    return offset;
  }

  boolean resident() {
    return state[RESIDENT] == Constants.SAFE_TRUE;
  }

  boolean matchesId(byte[] id, short offset) {
    return Util.arrayCompare(data, state[ID], id, offset, (short) 32) == 0;
  }

  boolean matchesKey(byte[] key) {
    return (
      key.length == 64 &&
      Util.arrayCompare(data, state[SCOPE], key, (short) 0, (short) 32) == 0 &&
      Util.arrayCompare(data, state[RP_HASH], key, (short) 32, (short) 32) == 0
    );
  }

  boolean sameUser(Credential other) {
    return (
      state[USER_ID_LENGTH] == other.state[USER_ID_LENGTH] &&
      Util.arrayCompare(
        data,
        state[USER_ID],
        other.data,
        other.state[USER_ID],
        state[USER_ID_LENGTH]
      ) ==
      0
    );
  }

  boolean sameId(Credential other) {
    return matchesId(other.data, other.state[ID]);
  }

  boolean matchesPublicKey(byte[] point) {
    return Util.arrayCompare(data, state[PUBLIC_KEY], point, (short) 0, (short) 65) == 0;
  }

  void copyId(byte[] dest, short offset) {
    Util.arrayCopyNonAtomic(data, state[ID], dest, offset, (short) 32);
  }

  void copyRPHash(byte[] dest, short offset) {
    Util.arrayCopyNonAtomic(data, state[RP_HASH], dest, offset, (short) 32);
  }

  byte[] key() {
    byte[] key = Utils.makeGlobalByteArray((short) 64);
    writeKey(key, (short) 0);
    return key;
  }

  short writeKey(byte[] dest, short offset) {
    Util.arrayCopyNonAtomic(data, state[SCOPE], dest, offset, (short) 32);
    copyRPHash(dest, (short) (offset + 32));

    return 64;
  }

  byte[] index() {
    return index(data, state[ID]);
  }

  boolean create(Monoid monoid, byte[] window) {
    short length = getLength();
    if (length > (short) (window.length - 74)) {
      return monoid.create(index(), key(), null, this, false) != null;
    }
    Util.setShort(window, (short) 0, CREDENTIAL_TYPE);
    Util.arrayCopyNonAtomic(data, state[ID], window, (short) 2, (short) 8);
    writeKey(window, (short) 10);
    read((short) 0, window, (short) 74, length);

    // Index, lookup key and record share separate ranges of the borrowed APDU buffer.
    return monoid.createData(
      window,
      (short) 0,
      window,
      (short) 10,
      (short) 64,
      null,
      window,
      (short) 74,
      length,
      false
    );
  }

  static byte[] index(byte[] id) {
    return index(id, (short) 0);
  }

  private static byte[] index(byte[] id, short offset) {
    byte[] index = Utils.makeGlobalByteArray((short) 10);
    Util.setShort(index, (short) 0, CREDENTIAL_TYPE);
    Util.arrayCopyNonAtomic(id, offset, index, (short) 2, (short) 8);
    return index;
  }

  byte[] context() {
    byte[] context = Utils.makeGlobalByteArray((short) (Constants.DERIVATION_CONTEXT.length + 64));
    writeContext(context, (short) 0);
    return context;
  }

  static byte[] context(byte[] id, byte[] rpHash) {
    byte[] context = Utils.makeGlobalByteArray((short) (Constants.DERIVATION_CONTEXT.length + 64));
    writeContext(id, rpHash, context, (short) 0);
    return context;
  }

  short writeContext(byte[] dest, short offset) {
    return writeContext(data, state[ID], data, state[RP_HASH], dest, offset);
  }

  static short writeContext(byte[] id, byte[] rpHash, byte[] dest, short offset) {
    return writeContext(id, (short) 0, rpHash, (short) 0, dest, offset);
  }

  private static short writeContext(
    byte[] id,
    short idOffset,
    byte[] rpHash,
    short rpOffset,
    byte[] dest,
    short offset
  ) {
    offset = Util.arrayCopyNonAtomic(
      Constants.DERIVATION_CONTEXT,
      (short) 0,
      dest,
      offset,
      (short) Constants.DERIVATION_CONTEXT.length
    );
    offset = Util.arrayCopyNonAtomic(rpHash, rpOffset, dest, offset, (short) 32);
    Util.arrayCopyNonAtomic(id, idOffset, dest, offset, (short) 32);
    return (short) (Constants.DERIVATION_CONTEXT.length + 64);
  }

  void writeDescriptor(CBORWriter writer) {
    LibCOSE.writeDescriptor(writer, data, state[ID], (short) 32);
  }

  void writePublicKey(CBORWriter writer) {
    LibCOSE.writePublicKey(writer, data, state[PUBLIC_KEY], (short) -7);
  }

  void writeUser(CBORWriter writer, boolean verified) {
    boolean unnamed = state[USER_NAME] == 0 && state[USER_DISPLAY_NAME] == 0;

    writer.map(
      (short) (1 +
        (verified && state[USER_NAME] != 0 ? 1 : 0) +
        (verified && (state[USER_DISPLAY_NAME] != 0 || unnamed) ? 1 : 0))
    );
    writer.text(KEY_ID);
    writer.bytes(data, state[USER_ID], state[USER_ID_LENGTH]);

    if (verified && state[USER_NAME] != 0) {
      writer.text(KEY_NAME);
      writeName(writer, state[USER_NAME], state[USER_NAME_LENGTH]);
    }

    if (verified && state[USER_DISPLAY_NAME] != 0) {
      writer.text(KEY_DISPLAY_NAME);
      writeName(writer, state[USER_DISPLAY_NAME], state[USER_DISPLAY_NAME_LENGTH]);
    } else if (verified && unnamed) {
      writer.text(KEY_DISPLAY_NAME);
      writer.text(label, (short) 1, (short) 18);
    }
  }

  private void writeName(CBORWriter writer, short offset, short length) {
    if (length == 0) {
      writer.text(label, (short) 1, (short) 18);
      return;
    }

    if (length > 45) {
      length = 45;

      // Keep the complete index visible within CTAP's 64-byte name limit.
      while ((data[(short) (offset + length)] & 0xC0) == 0x80) {
        length--;
      }
    }

    writer.textLength((short) (length + label.length));
    writer.rawBytes(data, offset, length);
    writer.rawBytes(label, (short) 0, (short) label.length);
  }

  private void updateLabel() {
    label[0] = ' ';
    label[1] = '[';

    for (short index = 0; index < 8; index++) {
      byte value = data[(short) (state[ID] + index)];
      label[(short) (2 + index * 2)] = hex((byte) ((value >> 4) & 0x0F));
      label[(short) (3 + index * 2)] = hex((byte) (value & 0x0F));
    }

    label[18] = ']';
  }

  private static byte hex(byte value) {
    return (byte) (value < 10 ? '0' + value : 'A' + value - 10);
  }

  private static short encodedLength(
    byte[] id,
    byte[] rpHash,
    byte[] scope,
    CredentialInput input
  ) {
    // Map, version, resident and the fixed 65-byte public key occupy 73 bytes.
    short length = (short) (73 +
      fieldLength((short) id.length) +
      fieldLength((short) rpHash.length) +
      fieldLength((short) scope.length));
    for (short field = 0; field < 4; field++) {
      length += fieldLength(input.length(field));
    }
    if (length > CTAP.MAX_MESSAGE_LENGTH) {
      ISOException.throwIt(CTAP.LIMIT_EXCEEDED);
    }
    return length;
  }

  private static short fieldLength(short length) {
    if (length < 0) {
      return 0;
    }
    if (length > CTAP.MAX_MESSAGE_LENGTH) {
      ISOException.throwIt(CTAP.LIMIT_EXCEEDED);
    }
    return (short) (1 + CBORWriter.metadataLength(length) + length);
  }

  @Override
  public short getLength() {
    return state[LENGTH];
  }

  @Override
  public void read(short dataOffset, byte[] buffer, short bufferOffset, short length) {
    Util.arrayCopyNonAtomic(data, dataOffset, buffer, bufferOffset, length);
  }
}
