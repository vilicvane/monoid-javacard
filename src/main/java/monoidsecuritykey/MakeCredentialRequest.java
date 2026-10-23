package monoidsecuritykey;

import static monoidsecuritykey.Constants.KEY_ALG;
import static monoidsecuritykey.Constants.KEY_DISPLAY_NAME;
import static monoidsecuritykey.Constants.KEY_ID;
import static monoidsecuritykey.Constants.KEY_NAME;
import static monoidsecuritykey.Constants.KEY_PUBLIC_KEY;
import static monoidsecuritykey.Constants.KEY_RK;
import static monoidsecuritykey.Constants.KEY_TYPE;
import static monoidsecuritykey.Constants.KEY_UP;
import static monoidsecuritykey.Constants.KEY_UV;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import monoidlib.CBORReader;

/** Consumes registration fields once; PIN verification follows complete structural validation. */
final class MakeCredentialRequest {

  private static final short[] FIELDS = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  private final Object[] entityFields = { KEY_ID, KEY_NAME, KEY_DISPLAY_NAME };
  private final Object[] parameterFields = { KEY_TYPE, KEY_ALG };
  private final Object[] optionFields = { KEY_RK, KEY_UV, KEY_UP };
  private static final short EXCLUDE = 0;
  private static final short PIN_AUTH = 1;
  private static final short PIN_PROTOCOL = 2;
  private static final short OPTIONS = 3;
  private final short[] state = JCSystem.makeTransientShortArray(
    (short) 4,
    JCSystem.CLEAR_ON_DESELECT
  );
  final CredentialInput input = new CredentialInput();
  final byte[] clientDataHash = new byte[32];

  void read(CBORReader reader) {
    for (short index = 0; index < state.length; index++) {
      state[index] = 0;
    }
    input.read(CredentialInput.USER_NAME, null);
    input.read(CredentialInput.USER_DISPLAY_NAME, null);
    short count = reader.map();
    short seen = 0;
    for (short index = 0; index < count; index++) {
      short field = reader.readKey(FIELDS, true);
      seen = mark(seen, field);
      switch (field) {
        case 0:
          reader.bytes(clientDataHash, (short) 0, (short) 32);
          break;
        case 1:
          entity(reader, false);
          break;
        case 2:
          entity(reader, true);
          break;
        case 3:
          parameters(reader);
          break;
        case 4:
          state[EXCLUDE] = reader.getOffset();
          reader.skip();
          break;
        case 6:
          options(reader);
          break;
        case 7:
          state[PIN_AUTH] = reader.getOffset();
          reader.skip();
          break;
        case 8:
          state[PIN_PROTOCOL] = reader.getOffset();
          reader.skip();
          break;
        default:
          reader.skip();
      }
    }
    assertRequired(seen, (short) 15);
    Command.assertEmpty(reader);
  }

  boolean resident() {
    return (state[OPTIONS] & 1) != 0;
  }

  boolean requestedUV() {
    return (state[OPTIONS] & 2) != 0;
  }

  short excludeOffset() {
    return state[EXCLUDE];
  }

  short pinAuthOffset() {
    return state[PIN_AUTH];
  }

  short pinProtocolOffset() {
    return state[PIN_PROTOCOL];
  }

  private void entity(CBORReader reader, boolean user) {
    short count = reader.map();
    short seen = 0;
    for (short index = 0; index < count; index++) {
      short field = reader.readKey(entityFields);
      seen = mark(seen, field);
      if (field == 0) {
        short target = user ? CredentialInput.USER_ID : CredentialInput.RP_ID;
        input.read(target, reader);
        short length = input.length(target);
        if (length == 0 || length > (user ? (short) 64 : (short) 254)) {
          ISOException.throwIt(CTAP.INVALID_LENGTH);
        }
      } else if (user && field > 0) {
        input.read(
          field == 1 ? CredentialInput.USER_NAME : CredentialInput.USER_DISPLAY_NAME,
          reader
        );
      } else {
        // Match the depth of the original top-level structural scan.
        reader.skip((byte) 1);
      }
    }
    assertRequired(seen, (short) 1);
  }

  private void parameters(CBORReader reader) {
    short count = reader.array();
    boolean supported = false;
    for (short index = 0; index < count; index++) {
      short entries = reader.map();
      short seen = 0;
      boolean publicKey = false;
      short algorithm = 0;
      for (short entry = 0; entry < entries; entry++) {
        short field = reader.readKey(parameterFields);
        seen = mark(seen, field);
        if (field == 0) {
          publicKey = reader.textMatches(KEY_PUBLIC_KEY);
        } else if (field == 1) {
          algorithm = reader.integer();
        } else {
          reader.skip((byte) 2);
        }
      }
      assertRequired(seen, (short) 3);
      supported |= publicKey && algorithm == -7;
    }
    if (!supported) {
      ISOException.throwIt(CTAP.UNSUPPORTED_ALGORITHM);
    }
  }

  private void options(CBORReader reader) {
    short count = reader.map();
    short seen = 0;
    for (short index = 0; index < count; index++) {
      short field = reader.readKey(optionFields);
      seen = mark(seen, field);
      if (field == 0 || field == 1) {
        if (reader.bool()) {
          state[OPTIONS] |= (short) (1 << field);
        }
      } else if (field == 2) {
        ISOException.throwIt(CTAP.INVALID_OPTION);
      } else {
        reader.skip((byte) 1);
      }
    }
  }

  private static short mark(short seen, short field) {
    if (field < 0) {
      return seen;
    }
    short bit = (short) (1 << field);
    if ((seen & bit) != 0) {
      ISOException.throwIt(CTAP.INVALID_CBOR);
    }
    return (short) (seen | bit);
  }

  private static void assertRequired(short seen, short required) {
    if ((seen & required) != required) {
      ISOException.throwIt(CTAP.MISSING_PARAMETER);
    }
  }
}
