package tests;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import monoid.CBORBufferReader;
import monoid.CBORBufferWriter;
import monoid.CBORMap;
import monoid.Text;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CBORMapTest {

  private final Object[] keys = {
    Text.index,
    Text.derivation,
    Text.cipher,
    Text.digest,
    Text.message,
  };
  private final Object[] derivationKeys = { Text.type, Text.path };

  @Test
  public void readReorderedNestedMaps() {
    for (boolean indefinite : new boolean[] { false, true }) {
      CBORBufferWriter writer = new CBORBufferWriter();

      if (indefinite) {
        writer.map();
      } else {
        writer.map((short) 3);
      }

      writer.text(Text.cipher);
      writer.text("ecdsa".getBytes());
      writer.text(Text.derivation);

      if (indefinite) {
        writer.map();
      } else {
        writer.map((short) 2);
      }

      writer.text(Text.path);
      writer.bytes(new byte[] { 1, 2, 3, 4 });
      writer.text(Text.type);
      writer.text("bip32".getBytes());

      if (indefinite) {
        writer.br();
      }

      writer.text(Text.index);
      writer.bytes(new byte[] { 5, 6 });

      if (indefinite) {
        writer.br();
      }

      CBORBufferReader reader = new CBORBufferReader(writer.getDataBuffer());
      CBORMap request = reader.map(keys);
      CBORMap derivation = request.requireKey(Text.derivation).map(derivationKeys);

      Assertions.assertArrayEquals("bip32".getBytes(), derivation.requireKey(Text.type).text());
      Assertions.assertArrayEquals(new byte[] { 5, 6 }, request.requireKey(Text.index).bytes());
      Assertions.assertArrayEquals(
        new byte[] { 1, 2, 3, 4 },
        derivation.requireKey(Text.path).bytes()
      );
      Assertions.assertArrayEquals("ecdsa".getBytes(), request.requireKey(Text.cipher).text());
      Assertions.assertFalse(request.key(Text.message));
    }
  }

  @Test
  public void skipUnknownNestedValues() {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 3);
    writer.text("unknown".getBytes());
    writer.array();
    writer.map((short) 1);
    writer.text("nested".getBytes());
    writer.bytes(new byte[] { 1, 2, 3 });
    writer.bool(true);
    writer.br();
    writer.text(Text.index);
    writer.bytes(new byte[] { 4, 5 });
    writer.text("other".getBytes());
    writer.map();
    writer.text("ignored".getBytes());
    writer.integer((short) -1);
    writer.br();

    CBORBufferReader reader = new CBORBufferReader(writer.getDataBuffer());
    CBORMap request = reader.map(keys);

    Assertions.assertEquals(writer.getDataBuffer().length, reader.getOffset());
    Assertions.assertArrayEquals(new byte[] { 4, 5 }, request.requireKey(Text.index).bytes());
  }

  @Test
  public void useFirstDuplicateValue() {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    writer.text(Text.index);
    writer.bytes(new byte[] { 1, 2 });
    writer.text(Text.index);
    writer.bool(false);

    CBORMap request = new CBORBufferReader(writer.getDataBuffer()).map(keys);

    Assertions.assertArrayEquals(new byte[] { 1, 2 }, request.requireKey(Text.index).bytes());
  }

  @Test
  public void matchKeyContent() {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 1);
    writer.text(Text.index);
    writer.bytes(new byte[] { 1, 2 });

    CBORMap request = new CBORBufferReader(writer.getDataBuffer()).map(keys);

    Assertions.assertArrayEquals(
      new byte[] { 1, 2 },
      request.requireKey("index".getBytes()).bytes()
    );
    Assertions.assertFalse(request.key("unknown".getBytes()));
  }

  @Test
  public void deferValueTypeValidationUntilRead() {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    writer.text(Text.message);
    writer.bool(true);
    writer.text(Text.cipher);
    writer.text("ecdsa".getBytes());

    CBORMap request = new CBORBufferReader(writer.getDataBuffer()).map(keys);

    Assertions.assertArrayEquals("ecdsa".getBytes(), request.requireKey(Text.cipher).text());

    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      request.requireKey(Text.message).bytes()
    );

    Assertions.assertEquals(ISO7816.SW_WRONG_DATA, exception.getReason());
  }

  @Test
  public void borrowMessageWithinOriginalBuffer() {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    writer.text(Text.message);
    writer.bytes(new byte[] { 1, 2, 3 });
    writer.text(Text.cipher);
    writer.text("ed25519".getBytes());

    byte[] payload = writer.getDataBuffer();
    CBORBufferReader reader = new CBORBufferReader(payload);
    CBORMap request = reader.map(keys);
    short length = request.requireKey(Text.message).bytesLength();
    short offset = reader.getOffset();

    Assertions.assertSame(payload, reader.getChunk(offset));
    Assertions.assertEquals(3, length);
    Assertions.assertArrayEquals(
      new byte[] { 1, 2, 3 },
      Arrays.copyOfRange(payload, offset, offset + length)
    );
    Assertions.assertArrayEquals("ed25519".getBytes(), request.requireKey(Text.cipher).text());
    Assertions.assertArrayEquals(
      new byte[] { 1, 2, 3 },
      Arrays.copyOfRange(reader.getChunk(offset), offset, offset + length)
    );
  }

  @Test
  public void rejectMissingRequiredFields() {
    for (String payload : new String[] { "a0", "bfff" }) {
      CBORMap request = new CBORBufferReader(Hex.decode(payload)).map(keys);

      Assertions.assertFalse(request.key(Text.index));

      ISOException exception = Assertions.assertThrows(ISOException.class, () ->
        request.requireKey(Text.index)
      );

      Assertions.assertEquals(ISO7816.SW_WRONG_DATA, exception.getReason());
    }
  }

  @Test
  public void rejectInvalidMapBoundaries() {
    for (String payload : new String[] {
      "a165696e64657859040000",
      "a165696e646578",
      "bf65696e6465784101",
      "a1ff",
      "a10100",
      "a167756e6b6e6f776e824101",
    }) {
      ISOException exception = Assertions.assertThrows(ISOException.class, () ->
        new CBORBufferReader(Hex.decode(payload)).map(keys)
      );

      Assertions.assertEquals(ISO7816.SW_WRONG_DATA, exception.getReason());
    }
  }
}
