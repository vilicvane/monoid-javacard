package monoidsecuritykey;

import com.licel.jcardsim.smartcardio.CardSimulator;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.framework.ISOException;
import monoidlib.CBORBufferWriter;
import monoidlib.CBORReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CredentialInputTest {

  @BeforeEach
  public void initialize() {
    new CardSimulator();
  }

  @Test
  public void rangedInputProducesTheExistingRecordAndOwnsBytesBeforeRequestReuse() {
    byte[] rp = "example.invalid".getBytes(StandardCharsets.UTF_8);
    byte[] user = { 0, 1, 2, (byte) 0xff };
    byte[] name = "\u7528\u6237".getBytes(StandardCharsets.UTF_8);
    byte[] empty = new byte[0];
    byte[] request = new byte[256];
    CredentialInput input = new CredentialInput();
    read(input, request, rp, user, name, empty);
    Credential actual = Credential.create(
      new byte[32],
      new byte[32],
      input,
      true,
      new byte[65],
      null
    );
    byte[] expected = encoded(
      new Credential(new byte[32], new byte[32], rp, user, name, empty, true, new byte[65])
    );
    Assertions.assertArrayEquals(expected, encoded(actual));
    Arrays.fill(request, (byte) 0xcc);
    Assertions.assertArrayEquals(expected, encoded(actual));
  }

  @Test
  public void nameTruncationConsumesTheFullValueAndKeepsOnlyCompleteCodePoints() {
    String[] points = { "\u00e9", "\u7528", "\ud83d\ude00" };
    for (String point : points) {
      byte[] utf8 = point.getBytes(StandardCharsets.UTF_8);
      for (int prefix : new int[] { 64 - utf8.length, 65 - utf8.length, 64 }) {
        byte[] text = new byte[prefix + utf8.length + 1];
        Arrays.fill(text, 0, prefix, (byte) 'a');
        System.arraycopy(utf8, 0, text, prefix, utf8.length);
        text[text.length - 1] = 'z';
        CBORReader reader = textReader(text);
        CredentialInput input = new CredentialInput();
        input.read(CredentialInput.USER_NAME, reader);
        Assertions.assertTrue(reader.atEnd());
        int length = prefix + utf8.length <= 64 ? prefix + utf8.length : prefix;
        byte[] encoded = new byte[80];
        CBORBufferWriter writer = new CBORBufferWriter(encoded, (short) 0, CTAP.LIMIT_EXCEEDED);
        input.write(writer, CredentialInput.USER_NAME);
        byte[] actual = new CBORReader(encoded, (short) 0, writer.getLength()).text();
        Assertions.assertArrayEquals(Arrays.copyOf(text, length), actual);
      }
    }
  }

  @Test
  public void invalidUtf8BeyondTheRetainedPrefixStillFails() {
    byte[] text = new byte[66];
    Arrays.fill(text, (byte) 'a');
    text[64] = (byte) 0xc3;
    text[65] = 0x28;
    CredentialInput input = new CredentialInput();
    Assertions.assertEquals(
      CTAP.INVALID_CBOR,
      Assertions.assertThrows(ISOException.class, () ->
        input.read(CredentialInput.USER_NAME, textReader(text))
      ).getReason()
    );
  }

  @Test
  public void reusingInputClearsMissingNamesButPreservesPresentEmptyText() {
    CredentialInput input = new CredentialInput();
    byte[] rp = { 'r' };
    byte[] user = { 7 };
    byte[] buffer = new byte[128];
    read(input, buffer, rp, user, new byte[] { 'n' }, new byte[] { 'd' });
    Credential record = Credential.create(
      new byte[32],
      new byte[32],
      input,
      true,
      new byte[65],
      null
    );
    read(input, buffer, rp, user, null, new byte[0]);
    Assertions.assertSame(
      record,
      Credential.create(new byte[32], new byte[32], input, true, new byte[65], record)
    );
    Credential expected = new Credential(
      new byte[32],
      new byte[32],
      rp,
      user,
      null,
      new byte[0],
      true,
      new byte[65]
    );
    Assertions.assertArrayEquals(encoded(expected), encoded(record));
    byte[] replacement = new byte[128];
    read(input, replacement, new byte[] { 's' }, new byte[] { 8 }, null, null);
    Credential.create(new byte[32], new byte[32], input, false, new byte[65], record);
    expected = new Credential(
      new byte[32],
      new byte[32],
      new byte[] { 's' },
      new byte[] { 8 },
      null,
      null,
      false,
      new byte[65]
    );
    Assertions.assertArrayEquals(encoded(expected), encoded(record));
  }

  private static void read(
    CredentialInput input,
    byte[] buffer,
    byte[] rp,
    byte[] user,
    byte[] name,
    byte[] display
  ) {
    CBORBufferWriter writer = new CBORBufferWriter(buffer, (short) 7, CTAP.LIMIT_EXCEEDED);
    writer.text(rp);
    writer.bytes(user);
    if (name != null) {
      writer.text(name);
    }
    if (display != null) {
      writer.text(display);
    }
    CBORReader reader = new CBORReader(buffer, (short) 7, writer.getLength());
    input.read(CredentialInput.RP_ID, reader);
    input.read(CredentialInput.USER_ID, reader);
    input.read(CredentialInput.USER_NAME, name == null ? null : reader);
    input.read(CredentialInput.USER_DISPLAY_NAME, display == null ? null : reader);
    Assertions.assertTrue(reader.atEnd());
  }

  private static CBORReader textReader(byte[] value) {
    byte[] buffer = new byte[value.length + 10];
    CBORBufferWriter writer = new CBORBufferWriter(buffer, (short) 5, CTAP.LIMIT_EXCEEDED);
    writer.text(value);
    return new CBORReader(buffer, (short) 5, writer.getLength());
  }

  private static byte[] encoded(Credential credential) {
    byte[] result = new byte[credential.getLength()];
    credential.read((short) 0, result, (short) 0, (short) result.length);
    return result;
  }
}
