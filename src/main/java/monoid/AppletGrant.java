package monoid;

import monoidlib.CBORWriter;

final class AppletGrant {

  final byte[] aid;
  final byte[] tokenHash;
  final short[] types;
  final short[] writable;
  final Key[] keys;
  final Seed seed;

  AppletGrant(
    byte[] aid,
    byte[] tokenHash,
    short[] types,
    short[] writable,
    Key[] keys,
    Seed seed
  ) {
    this.aid = aid;
    this.tokenHash = tokenHash;
    this.types = types;
    this.writable = writable;
    this.keys = keys;
    this.seed = seed;
  }

  boolean allows(short type, boolean write) {
    if (types != null) {
      for (short index = 0; index < types.length; index++) {
        if (types[index] == type) {
          return !write || writable[index] == Constants.SAFE_TRUE;
        }
      }
    }

    return false;
  }

  short getMaxEncodedLength() {
    short length = (short) (32 + aid.length + tokenHash.length);

    if (types != null) {
      length += (short) (9 + types.length * 5);
    }

    if (keys != null) {
      length += 8;

      for (short index = 0; index < keys.length; index++) {
        length += keys[index].getMaxEncodedLength();
      }
    }

    if (seed != null) {
      length += (short) (32 + seed.index.length + seed.domain.length);
    }

    return length;
  }

  void write(CBORWriter writer) {
    short count = 2;

    if (types != null) {
      count++;
    }

    if (keys != null) {
      count++;
    }

    if (seed != null) {
      count++;
    }

    writer.map(count);
    writer.text(Text.aid);
    writer.bytes(aid);
    writer.text(Text.tokenHash);
    writer.bytes(tokenHash);

    if (types != null) {
      writer.text(Text.types);
      writer.array((short) types.length);

      for (short index = 0; index < types.length; index++) {
        writer.array((short) 2);
        writer.integer(types[index]);
        writer.bool(writable[index] == Constants.SAFE_TRUE);
      }
    }

    if (keys != null) {
      writer.text(Text.keys);
      writer.array((short) keys.length);

      for (short index = 0; index < keys.length; index++) {
        keys[index].write(writer);
      }
    }

    if (seed != null) {
      writer.text(Text.seed);
      writer.map((short) 2);
      writer.text(Text.index);
      writer.bytes(seed.index);
      writer.text(Text.domain);
      writer.bytes(seed.domain);
    }
  }

  static final class Key {

    final byte[] index;
    final short type;
    final byte[] derivation;
    final byte[] input;

    Key(byte[] index, short type, byte[] derivation, byte[] input) {
      this.index = index;
      this.type = type;
      this.derivation = derivation;
      this.input = input;
    }

    short getMaxEncodedLength() {
      return (short) (96 + index.length + (input != null ? input.length : 0));
    }

    void write(CBORWriter writer) {
      writer.map(derivation == null ? (short) 2 : 3);
      writer.text(Text.index);
      writer.bytes(index);
      writer.text(Text.type);
      writer.text(Safe.type(type));

      if (derivation != null) {
        writer.text(Text.derivation);
        writer.map(derivation == SLIP10Ed25519Derivation.NAME ? (short) 3 : 2);
        writer.text(Text.type);
        writer.text(derivation);

        if (derivation == SLIP10Ed25519Derivation.NAME) {
          writer.text(Text.curve);
          writer.text(EdwardsCurve.ED25519);
        }

        writer.text(derivation == Monoid001Derivation.NAME ? Text.context : Text.path);
        writer.bytes(input);
      }
    }
  }

  static final class Seed {

    final byte[] index;
    final byte[] domain;

    Seed(byte[] index, byte[] domain) {
      this.index = index;
      this.domain = domain;
    }
  }
}
