package monoid;

import javacard.framework.Util;
import monoidlib.CBORMap;
import monoidlib.CBORReader;
import monoidlib.Utils;

public final class CommandSetAppletGrant extends Command {

  private final Object[] fields = { Text.aid, Text.types, Text.keys, Text.seed };
  private final Object[] keyFields = {
    Text.index,
    Text.type,
    Text.derivation,
    Text.seed,
    Text.curve,
    Text.path,
  };
  private final Object[] derivationFields = { Text.type, Text.curve, Text.path, Text.context };
  private final Object[] seedFields = { Text.index, Text.domain };

  @Override
  protected void run() {
    Safe safe = MonoidApplet.safe;
    AppletGrants grants = safe.getAppletGrants();
    grants.assertManagement();

    CBORMap request = reader.map(fields);
    request.requireKey(Text.aid);
    byte[] aid = readBytes();

    if (aid.length < 5 || aid.length > 16) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    }

    short[] types = null;
    short[] writable = null;

    if (request.key(Text.types)) {
      short count = readArrayLength();
      safe.checkStorage((short) (count * 4));
      types = new short[count];
      writable = new short[count];

      for (short index = 0; index < count; index++) {
        if (reader.array() != 2) {
          MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        }

        short type = reader.integer();

        if (
          (type >= 0 && type < Safe.TYPE_RESERVED_END) || type == Safe.TYPE_RESERVED_EXTENSION_MARK
        ) {
          MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        }

        for (short previous = 0; previous < index; previous++) {
          if (types[previous] == type) {
            MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
          }
        }

        types[index] = type;
        writable[index] = reader.bool() ? Constants.SAFE_TRUE : Constants.SAFE_FALSE;
      }
    }

    AppletGrant.Key[] keys = null;

    if (request.key(Text.keys)) {
      short count = readArrayLength();
      safe.checkStorage((short) (count * 2));
      keys = new AppletGrant.Key[count];

      for (short index = 0; index < count; index++) {
        short offset = reader.getOffset();
        reader.skip();
        short next = reader.getOffset();
        // Work around CAP converter lookup failures by referencing setOffset's declaring class.
        ((CBORReader) reader).setOffset(offset);
        keys[index] = readKey();
        // Work around CAP converter lookup failures by referencing setOffset's declaring class.
        ((CBORReader) reader).setOffset(next);
      }
    }

    AppletGrant.Seed seed = null;

    if (request.key(Text.seed)) {
      CBORMap source = reader.map(seedFields);
      source.requireKey(Text.index);
      byte[] index = readIndex();

      if (!Safe.isTypeSeed(Util.getShort(index, Safe.INDEX_TYPE_OFFSET))) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      }

      assertSourceLength(index, Keystore.SEED_512_LENGTH);
      source.requireKey(Text.domain);
      seed = new AppletGrant.Seed(index, readBytes());
    }

    grants.set(aid, types, writable, keys, seed);
    sendEmptyMap();
  }

  private AppletGrant.Key readKey() {
    CBORMap key = reader.map(keyFields);
    key.requireKey(Text.index);
    byte[] index = readIndex();
    short type = Util.getShort(index, Safe.INDEX_TYPE_OFFSET);
    short declaredType = Safe.type(key.requireKey(Text.type));

    if (
      declaredType != (Safe.isTypeSeed(type) ? (short) (type & Safe.TYPE_CATEGORY_MASK) : type) ||
      key.key(Text.seed) ||
      key.key(Text.curve) ||
      key.key(Text.path)
    ) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    }

    if (!Safe.isTypeSeed(type)) {
      if (
        (type != Safe.TYPE_WEIERSTRASS_SECP256K1 &&
          type != Safe.TYPE_WEIERSTRASS_SECP256R1 &&
          type != Safe.TYPE_EDWARDS_ED25519) ||
        key.key(Text.derivation)
      ) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      }

      assertSourceLength(index, (short) 32);
      return new AppletGrant.Key(index, declaredType, null, null);
    }

    assertSourceLength(index, Keystore.SEED_512_LENGTH);
    CBORMap derivation = key.requireKey(Text.derivation).map(derivationFields);
    byte[] name = derivation.requireKey(Text.type).text();
    byte[] algorithm;
    byte[] input;

    if (Utils.isEqual(Monoid001Derivation.NAME, name)) {
      if (derivation.key(Text.curve) || derivation.key(Text.path)) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      }

      algorithm = Monoid001Derivation.NAME;
      derivation.requireKey(Text.context);
      input = readBytes();
    } else {
      if (Utils.isEqual(BIP32Derivation.NAME, name)) {
        if (derivation.key(Text.curve)) {
          MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        }

        algorithm = BIP32Derivation.NAME;
      } else if (Utils.isEqual(SLIP10Ed25519Derivation.NAME, name)) {
        if (!Utils.isEqual(EdwardsCurve.ED25519, derivation.requireKey(Text.curve).text())) {
          MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        }

        algorithm = SLIP10Ed25519Derivation.NAME;
      } else {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return null;
      }

      derivation.requireKey(Text.path);
      input = readBytes();

      if (input.length % BIP32Derivation.PATH_SEGMENT_LENGTH != 0) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      }

      if (algorithm == SLIP10Ed25519Derivation.NAME) {
        for (
          short offset = 0;
          offset < input.length;
          offset += BIP32Derivation.PATH_SEGMENT_LENGTH
        ) {
          if ((input[offset] & (byte) 0x80) == 0) {
            MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
          }
        }
      }
    }

    return new AppletGrant.Key(index, declaredType, algorithm, input);
  }

  private void assertSourceLength(byte[] index, short length) {
    SafeItem item = MonoidApplet.safe.require(index);

    if (item.getStoredData().length != length) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    }
  }

  private short readArrayLength() {
    short length = reader.array();

    if (length < 0) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    }

    return length;
  }

  private byte[] readIndex() {
    byte[] index = readBytes();

    if (index.length != Safe.INDEX_LENGTH) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    }

    return index;
  }

  private byte[] readBytes() {
    short offset = reader.getOffset();
    short length = reader.bytesLength();
    MonoidApplet.safe.checkStorage(length);
    byte[] bytes = new byte[length];
    // Work around CAP converter lookup failures by referencing setOffset's declaring class.
    ((CBORReader) reader).setOffset(offset);
    reader.bytes(bytes, (short) 0);
    return bytes;
  }
}
