package monoidsecuritykey;

import static monoidsecuritykey.Constants.KEY_ID;
import static monoidsecuritykey.Constants.KEY_PUBLIC_KEY;
import static monoidsecuritykey.Constants.KEY_TYPE;

import javacard.framework.ISOException;
import javacard.framework.Util;
import monoidlib.CBORMap;
import monoidlib.CBORReader;
import monoidlib.CBORWriter;

final class LibCOSE {

  static final short[] KEY_AGREEMENT_FIELDS = { 1, 3, -1, -2, -3 };

  static void writePublicKey(CBORWriter writer, byte[] point, short algorithm) {
    writePublicKey(writer, point, (short) 0, algorithm);
  }

  static void writePublicKey(CBORWriter writer, byte[] point, short offset, short algorithm) {
    writer.map((short) 5);
    writer.integer((short) 1);
    writer.integer((short) 2);
    writer.integer((short) 3);
    writer.integer(algorithm);
    writer.integer((short) -1);
    writer.integer((short) 1);
    writer.integer((short) -2);
    writer.bytes(point, (short) (offset + 1), (short) 32);
    writer.integer((short) -3);
    writer.bytes(point, (short) (offset + 33), (short) 32);
  }

  static byte[] readKeyAgreement(CBORReader reader) {
    byte[] point = new byte[65];
    readKeyAgreement(reader, new CBORMap(KEY_AGREEMENT_FIELDS), point, (short) 0);
    return point;
  }

  static void readKeyAgreement(CBORReader reader, CBORMap fields, byte[] point, short offset) {
    fields.read(reader);
    if (
      fields.requireKey((short) 1).integer() != 2 ||
      fields.requireKey((short) 3).integer() != -25 ||
      fields.requireKey((short) -1).integer() != 1
    ) {
      ISOException.throwIt(CTAP.INVALID_PARAMETER);
    }
    point[offset] = 4;
    fields.requireKey((short) -2).bytes(point, (short) (offset + 1), (short) 32);
    fields.requireKey((short) -3).bytes(point, (short) (offset + 33), (short) 32);
  }

  static void writeDescriptor(CBORWriter writer, byte[] id) {
    writeDescriptor(writer, id, (short) 0, (short) id.length);
  }

  static void writeDescriptor(CBORWriter writer, byte[] id, short offset, short length) {
    writer.map((short) 2);
    writer.text(KEY_ID);
    writer.bytes(id, offset, length);
    writer.text(KEY_TYPE);
    writer.text(KEY_PUBLIC_KEY);
  }

  static byte[] signatureDER(byte[] signature) {
    short r = integerOffset(signature, (short) 0);
    short s = integerOffset(signature, (short) 32);
    byte[] encoded = new byte[signatureLength(signature, r, s)];
    writeSignature(signature, encoded, (short) 0, r, s);
    return encoded;
  }

  static short signatureDER(byte[] signature, byte[] dest, short offset) {
    return writeSignature(
      signature,
      dest,
      offset,
      integerOffset(signature, (short) 0),
      integerOffset(signature, (short) 32)
    );
  }

  private static short integerOffset(byte[] signature, short start) {
    short offset = start;
    while (offset < (short) (start + 31) && signature[offset] == 0) {
      offset++;
    }
    return offset;
  }

  private static short signatureLength(byte[] signature, short r, short s) {
    return (short) (6 + 32 - r + 64 - s + (signature[r] < 0 ? 1 : 0) + (signature[s] < 0 ? 1 : 0));
  }

  private static short writeSignature(
    byte[] signature,
    byte[] dest,
    short offset,
    short r,
    short s
  ) {
    short rLength = (short) (32 - r);
    short sLength = (short) (64 - s);
    short length = signatureLength(signature, r, s);
    dest[offset] = 0x30;
    dest[(short) (offset + 1)] = (byte) (length - 2);
    short next = writeInteger(signature, r, rLength, dest, (short) (offset + 2));
    writeInteger(signature, s, sLength, dest, next);
    return length;
  }

  private static short writeInteger(
    byte[] value,
    short offset,
    short length,
    byte[] out,
    short outOffset
  ) {
    boolean prefix = value[offset] < 0;
    out[outOffset++] = 2;
    out[outOffset++] = (byte) (length + (prefix ? 1 : 0));
    if (prefix) {
      out[outOffset++] = 0;
    }
    return Util.arrayCopyNonAtomic(value, offset, out, outOffset, length);
  }
}
