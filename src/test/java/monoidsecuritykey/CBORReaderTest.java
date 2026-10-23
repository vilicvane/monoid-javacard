package monoidsecuritykey;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import javacard.framework.ISOException;
import monoidlib.CBORMap;
import monoidlib.CBORReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CBORReaderTest {

  @Test
  public void strictReaderDoesNotAllocateNavigationOrSnapshots() throws Exception {
    CBORReader reader = reader("a1014101");
    CBORMap fields = reader.map(new short[] { 1 });
    Assertions.assertArrayEquals(new byte[] { 1 }, fields.requireKey((short) 1).bytes());
    for (String name : new String[] { "navigation", "snapshots" }) {
      Field field = CBORReader.class.getDeclaredField(name);
      field.setAccessible(true);
      Assertions.assertNull(field.get(reader));
    }
    Field state = CBORReader.class.getDeclaredField("state");
    state.setAccessible(true);
    Assertions.assertEquals(2, ((short[]) state.get(reader)).length);
  }

  @Test
  public void textMatchesUsesTheCompleteValidatedTextRange() {
    CBORReader reader = reader("6361626362616260");
    Assertions.assertTrue(reader.textMatches(new byte[] { 'a', 'b', 'c' }));
    Assertions.assertFalse(reader.textMatches(new byte[] { 'a', 'b', 'c' }));
    Assertions.assertTrue(reader.textMatches(new byte[0]));
    Assertions.assertTrue(reader.atEnd());
    Assertions.assertEquals(
      CTAP.INVALID_CBOR,
      Assertions.assertThrows(ISOException.class, () ->
        reader("63eda080").textMatches(new byte[0])
      ).getReason()
    );
  }

  @Test
  public void resetBoundsExcludePreviousRequestTail() {
    CBORReader reader = reader("420102");
    Assertions.assertArrayEquals(new byte[] { 1, 2 }, reader.bytes());
    reader.reset((short) 0, (short) 2);
    Assertions.assertEquals(
      CTAP.INVALID_CBOR,
      Assertions.assertThrows(ISOException.class, reader::bytesOffset).getReason()
    );
    reader.reset((short) 1, (short) 1);
    Assertions.assertEquals(1, reader.integer());
    Assertions.assertTrue(reader.atEnd());
  }

  @Test
  public void reusableMapDoesNotRetainMissingFields() {
    CBORReader reader = reader("a201020203a10104a201010102a10205");
    CBORMap fields = new CBORMap(new short[] { 1, 2 });
    fields.read(reader);
    Assertions.assertEquals(3, fields.requireKey((short) 2).integer());
    reader.setOffset((short) 5);
    fields.read(reader);
    Assertions.assertFalse(fields.key((short) 2));
    Assertions.assertEquals(4, fields.requireKey((short) 1).integer());
    reader.setOffset((short) 8);
    Assertions.assertEquals(
      CTAP.INVALID_CBOR,
      Assertions.assertThrows(ISOException.class, () -> fields.read(reader)).getReason()
    );
    reader.setOffset((short) 13);
    fields.read(reader);
    Assertions.assertFalse(fields.key((short) 1));
    Assertions.assertEquals(5, fields.requireKey((short) 2).integer());
  }

  @Test
  public void readsByteAndTextRangesWithoutChangingValidation() {
    CBORReader reader = reader("42010263e4b8ad");
    Assertions.assertEquals(1, reader.bytesOffset());
    Assertions.assertEquals(3, reader.getOffset());
    Assertions.assertEquals(4, reader.textOffset());
    Assertions.assertTrue(reader.atEnd());
    byte[] dest = new byte[4];
    reader.reset((short) 0, (short) 3);
    reader.bytes(dest, (short) 1, (short) 2);
    Assertions.assertArrayEquals(new byte[] { 0, 1, 2, 0 }, dest);
    reader.reset((short) 0, (short) 3);
    Assertions.assertEquals(
      CTAP.INVALID_LENGTH,
      Assertions.assertThrows(ISOException.class, () ->
        reader.bytes(dest, (short) 0, (short) 1)
      ).getReason()
    );
    Assertions.assertEquals(
      CTAP.INVALID_CBOR,
      Assertions.assertThrows(ISOException.class, () -> reader("63eda080").textOffset()).getReason()
    );
  }

  @Test
  public void skipsUnknownSimpleAndFloatingPointFields() {
    for (String encoded : new String[] {
      "e0",
      "f4",
      "f5",
      "f6",
      "f7",
      "f820",
      "f8ff",
      "f90000",
      "fa3f800000",
      "fb3ff0000000000000",
    }) {
      CBORReader reader = reader("a2010102" + encoded);
      CBORMap fields = reader.map(new short[] { 1 });
      Assertions.assertTrue(reader.atEnd(), encoded);
      Assertions.assertEquals(1, fields.requireKey((short) 1).integer(), encoded);
    }
  }

  @Test
  public void skipsWideIntegerKeysWithoutAliasingKnownKeys() {
    for (String key : new String[] {
      "198000",
      "19ffff",
      "1a00010000",
      "1affffffff",
      "1b0000000100000000",
      "1bffffffffffffffff",
      "398000",
      "39ffff",
      "3a00010000",
      "3bffffffffffffffff",
    }) {
      CBORReader reader = reader("a2010a" + key + "f6");
      CBORMap fields = reader.map(new short[] { 1, (short) 0x8000, -1 });
      Assertions.assertTrue(reader.atEnd(), key);
      Assertions.assertEquals(10, fields.requireKey((short) 1).integer(), key);
      Assertions.assertFalse(fields.key((short) 0x8000), key);
      Assertions.assertFalse(fields.key((short) -1), key);
    }

    CBORReader reader = reader("a1397fff01");
    CBORMap fields = reader.map(new short[] { (short) 0x8000 });
    Assertions.assertEquals(1, fields.requireKey((short) 0x8000).integer());
  }

  @Test
  public void unsupportedWideAlgorithmsDoNotPreventFindingES256() {
    CBORReader reader = reader("83a10339fffea1033bffffffffffffffffa10326");
    Assertions.assertEquals(3, reader.array());
    boolean supported = false;
    for (short index = 0; index < 3; index++) {
      CBORMap parameter = reader.map(new short[] { 3 });
      short next = reader.getOffset();
      short algorithm = parameter.requireKey((short) 3).integer();
      if (index < 2) {
        Assertions.assertEquals(CBORReader.INTEGER_OUT_OF_RANGE, algorithm);
      }
      supported |= algorithm == -7;
      reader.setOffset(next);
    }
    Assertions.assertTrue(supported);
    Assertions.assertTrue(reader.atEnd());
  }

  @Test
  public void integerMapSchemasKeepDenseSparseReorderedAndBoundaryKeysDistinct() {
    for (short[] keys : new short[][] { { 1, 2, 3 }, { 3, 1, 2 }, { 1, 3 }, { 1, 1, 3 } }) {
      CBORMap fields = reader("a3030c010a020b").map(keys);
      Assertions.assertEquals(10, fields.requireKey((short) 1).integer());
      Assertions.assertEquals(12, fields.requireKey((short) 3).integer());
      Assertions.assertFalse(fields.key((short) 0));
      Assertions.assertFalse(fields.key((short) 4));
      Assertions.assertEquals(
        CTAP.INVALID_CBOR,
        Assertions.assertThrows(ISOException.class, () ->
          reader("a201000101").map(keys)
        ).getReason()
      );
    }
    CBORMap boundary = reader("a2197fff1839397fff183a").map(new short[] { 32767, (short) -32768 });
    Assertions.assertEquals(57, boundary.requireKey((short) 32767).integer());
    Assertions.assertEquals(58, boundary.requireKey((short) -32768).integer());
    Assertions.assertFalse(boundary.key((short) -32767));
    Assertions.assertFalse(reader("a10100").map(new short[0]).key((short) 1));
  }

  @Test
  public void readsSignedShortBoundaries() {
    Assertions.assertEquals(32767, reader("197fff").integer());
    Assertions.assertEquals(-32768, reader("397fff").integer());
    Assertions.assertEquals(CBORReader.INTEGER_OUT_OF_RANGE, reader("198000").integer());
    Assertions.assertEquals(CBORReader.INTEGER_OUT_OF_RANGE, reader("398000").integer());
  }

  @Test
  public void rejectsNonminimalIntegersEvenInUnknownFields() {
    for (String value : new String[] {
      "1800",
      "1817",
      "1900ff",
      "1a0000ffff",
      "1b00000000ffffffff",
      "3800",
      "3817",
      "3900ff",
      "3a0000ffff",
      "3b00000000ffffffff",
    }) {
      assertInvalid("a2010102" + value);
    }
  }

  @Test
  public void rejectsInvalidAndTruncatedSimpleValues() {
    for (String value : new String[] {
      "f814",
      "f818",
      "f81f",
      "f8",
      "f900",
      "fa000000",
      "fb00000000000000",
      "fc",
      "ff",
    }) {
      assertInvalid("a2010102" + value);
    }
  }

  @Test
  public void validatesUTF8InReadAndSkippedValues() {
    for (String text : new String[] {
      "",
      "plain text",
      "用户",
      "\uD83D\uDD11",
      "\u007f\u0080\u07ff\u0800\ud7ff\ue000\uffff",
      "\uD800\uDC00\uDBFF\uDFFF",
    }) {
      byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
      byte[] encoded = new byte[bytes.length + 1];
      encoded[0] = (byte) (0x60 | bytes.length);
      System.arraycopy(bytes, 0, encoded, 1, bytes.length);
      CBORReader reader = new CBORReader(encoded, (short) 0, (short) encoded.length);
      Assertions.assertArrayEquals(bytes, reader.text());
      Assertions.assertTrue(reader.atEnd());
      reader.setOffset((short) 0);
      reader.skip();
      Assertions.assertTrue(reader.atEnd());
    }
  }

  @Test
  public void rejectsInvalidUTF8IncludingUnknownFieldsAndKeys() {
    for (String text : new String[] {
      "61ff",
      "6180",
      "62c080",
      "62c1bf",
      "61c2",
      "62c27f",
      "63e08080",
      "63eda080",
      "62e0a0",
      "64f0808080",
      "64f4908080",
      "64f5808080",
      "63f09080",
    }) {
      Assertions.assertEquals(
        CTAP.INVALID_CBOR,
        Assertions.assertThrows(ISOException.class, () -> reader(text).text()).getReason(),
        text
      );
      assertInvalid("a2010102" + text);
      Assertions.assertEquals(
        CTAP.INVALID_CBOR,
        Assertions.assertThrows(ISOException.class, () ->
          reader("a1" + text + "01").map(new Object[] { new byte[] { 'a' } })
        ).getReason(),
        text
      );
    }
  }

  @Test
  public void rejectsMalformedLengthsAndTags() {
    for (String value : new String[] {
      "5800",
      "59000100",
      "5a00000001ff",
      "5b0000000000000001ff",
      "590100",
      "5affffffff",
      "9f01ff",
      "c001",
    }) {
      assertInvalid("a2010102" + value);
    }
  }

  @Test
  public void stillRejectsDuplicateKnownKeys() {
    assertInvalid("a201010102");
  }

  @Test
  public void distinguishesMissingIntegerFieldsFromTheFirstValue() {
    CBORReader reader = reader("a10000");
    CBORMap fields = reader.map(new short[] { 0, 1 });
    Assertions.assertTrue(reader.atEnd());
    Assertions.assertFalse(fields.key((short) 1));
    Assertions.assertTrue(reader.atEnd());
    Assertions.assertEquals(0, fields.requireKey((short) 0).integer());
    Assertions.assertEquals(
      CTAP.MISSING_PARAMETER,
      Assertions.assertThrows(ISOException.class, () -> fields.requireKey((short) 1)).getReason()
    );
    Assertions.assertFalse(reader("a0").map(new short[] { 0 }).key((short) 0));
    Assertions.assertEquals(
      CTAP.INVALID_CBOR,
      Assertions.assertThrows(ISOException.class, () ->
        reader("a200000001").map(new short[] { 0 })
      ).getReason()
    );
  }

  @Test
  public void indexesEmptyTextKeysAtTheStartAndAfterAPrefix() {
    byte[] empty = new byte[0];
    byte[] missing = { 'x' };
    for (String prefix : new String[] { "", "00" }) {
      CBORReader reader = reader(prefix + "a16000");
      reader.setOffset((short) (prefix.length() / 2));
      CBORMap fields = reader.map(new Object[] { empty, missing });
      Assertions.assertEquals(0, fields.requireKey(empty).integer());
      Assertions.assertFalse(fields.key(missing));
    }
    Assertions.assertEquals(
      CTAP.INVALID_CBOR,
      Assertions.assertThrows(ISOException.class, () ->
        reader("a260006001").map(new Object[] { empty })
      ).getReason()
    );
  }

  private static void assertInvalid(String encoded) {
    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      reader(encoded).map(new short[] { 1 })
    );
    Assertions.assertEquals(CTAP.INVALID_CBOR, exception.getReason(), encoded);
  }

  private static CBORReader reader(String encoded) {
    byte[] bytes = new byte[encoded.length() / 2];
    for (short index = 0; index < bytes.length; index++) {
      bytes[index] = (byte) Integer.parseInt(encoded.substring(index * 2, index * 2 + 2), 16);
    }
    return new CBORReader(bytes, (short) 0, (short) bytes.length);
  }
}
