package monoidsecuritykey;

import javacard.framework.JCSystem;
import monoidlib.CBORReader;
import monoidlib.CBORWriter;

/** Reusable ranges in private input buffers; no APDU or foreign array is retained. */
final class CredentialInput {

  static final short RP_ID = 0;
  static final short USER_ID = 1;
  static final short USER_NAME = 2;
  static final short USER_DISPLAY_NAME = 3;

  private final Object[] buffers = new Object[4];
  private final short[] ranges = JCSystem.makeTransientShortArray(
    (short) 8,
    JCSystem.CLEAR_ON_DESELECT
  );

  CredentialInput() {}

  CredentialInput(byte[] rpId, byte[] userId, byte[] userName, byte[] userDisplayName) {
    set(RP_ID, rpId, (short) 0, length(rpId));
    set(USER_ID, userId, (short) 0, length(userId));
    set(USER_NAME, userName, (short) 0, length(userName));
    set(USER_DISPLAY_NAME, userDisplayName, (short) 0, length(userDisplayName));
  }

  void read(short field, CBORReader reader) {
    if (reader == null) {
      ranges[(short) (field * 2 + 1)] = -1;
      return;
    }
    short offset = field == USER_ID ? reader.bytesOffset() : reader.textOffset();
    short length = (short) (reader.getOffset() - offset);
    byte[] buffer = reader.getBuffer();
    if (field >= USER_NAME && length > 64) {
      length = 64;
      // The complete text was validated above. Keep only whole UTF-8 code points.
      while ((buffer[(short) (offset + length)] & 0xC0) == 0x80) {
        length--;
      }
    }
    set(field, buffer, offset, length);
  }

  byte[] buffer(short field) {
    return (byte[]) buffers[field];
  }

  short offset(short field) {
    return ranges[(short) (field * 2)];
  }

  short length(short field) {
    return ranges[(short) (field * 2 + 1)];
  }

  void write(CBORWriter writer, short field) {
    if (field == USER_ID) {
      writer.bytes(buffer(field), offset(field), length(field));
    } else {
      writer.text(buffer(field), offset(field), length(field));
    }
  }

  private void set(short field, byte[] buffer, short offset, short length) {
    if (buffers[field] != buffer) {
      buffers[field] = buffer;
    }
    ranges[(short) (field * 2)] = offset;
    ranges[(short) (field * 2 + 1)] = length;
  }

  private static short length(byte[] value) {
    return value == null ? (short) -1 : (short) value.length;
  }
}
