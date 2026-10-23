package monoidsecuritykey;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import monoidlib.CBORBufferWriter;
import monoidlib.CBORReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CredentialParsingTest {

  private static final int[] REQUIRED = { 1, 2, 3, 4, 5, 8, 9, 10 };
  private final byte[] id = filled(32, 1);
  private final byte[] rpHash = filled(32, 2);
  private final byte[] publicKey = filled(65, 3);
  private final byte[] scope = filled(32, 5);

  @BeforeEach
  public void initialize() {
    CardSimulator simulator = new CardSimulator();
    simulator.installApplet(AIDUtil.create("f06d6f6e6f69647b01"), TestApplet.class);
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create("f06d6f6e6f69647b01")));
  }

  @Test
  public void fieldsCanAppearInAnyOrderAndUnknownValuesAreSkipped() {
    byte[] encoded = record(new int[] { 9, 6, 2, 42, 10, 8, 5, 3, 7, 4, 1 }, "账户");
    Credential credential = read(encoded, null);
    Assertions.assertTrue(credential.matchesId(id, (short) 0));
    Assertions.assertArrayEquals(scope, Arrays.copyOf(credential.key(), 32));
    Assertions.assertArrayEquals(rpHash, Arrays.copyOfRange(credential.key(), 32, 64));
    Assertions.assertTrue(credential.matchesPublicKey(publicKey));
    Assertions.assertTrue(credential.resident());
    Assertions.assertEquals(encoded.length, credential.getLength());
  }

  @Test
  public void metadataMatchesBothScopeAndRelyingParty() {
    Credential credential = read(record(REQUIRED, null), null);
    byte[] key = new byte[64];
    System.arraycopy(scope, 0, key, 0, 32);
    System.arraycopy(rpHash, 0, key, 32, 32);

    Assertions.assertArrayEquals(key, credential.key());
    Assertions.assertTrue(credential.matchesKey(key));
    Assertions.assertFalse(credential.matchesKey(rpHash));
    credential.assertMetadata(credential.index(), (short) 0, key);

    byte[] output = new byte[68];
    Assertions.assertEquals(64, credential.writeKey(output, (short) 2));
    Assertions.assertArrayEquals(key, Arrays.copyOfRange(output, 2, 66));

    for (int offset : new int[] { 0, 32 }) {
      byte[] changed = key.clone();
      changed[offset] ^= 1;

      Assertions.assertFalse(credential.matchesKey(changed));
      ISOException error = Assertions.assertThrows(ISOException.class, () ->
        credential.assertMetadata(credential.index(), (short) 0, changed)
      );
      Assertions.assertEquals(CTAP.OTHER, error.getReason());
    }
  }

  @Test
  public void verifiedNamesExposeTheStableIndexWithoutChangingStoredNames() {
    byte[] encoded = record(new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, "账户");
    Credential credential = read(encoded, null);
    CBORReader user = user(credential, true);

    Assertions.assertEquals(3, user.map());
    Assertions.assertArrayEquals(Constants.KEY_ID, user.text());
    Assertions.assertArrayEquals(new byte[] { 4 }, user.bytes());
    Assertions.assertArrayEquals(Constants.KEY_NAME, user.text());
    Assertions.assertEquals("账户 [0101010101010101]", text(user));
    Assertions.assertArrayEquals(Constants.KEY_DISPLAY_NAME, user.text());
    Assertions.assertEquals("账户 [0101010101010101]", text(user));
    Assertions.assertTrue(user.atEnd());

    byte[] stored = new byte[credential.getLength()];
    credential.read((short) 0, stored, (short) 0, (short) stored.length);
    Assertions.assertArrayEquals(encoded, stored);
  }

  @Test
  public void namesAndIndexRemainHiddenWithoutUserVerification() {
    for (int[] fields : new int[][] { REQUIRED, { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } }) {
      CBORReader user = user(read(record(fields, "name"), null), false);

      Assertions.assertEquals(1, user.map());
      Assertions.assertArrayEquals(Constants.KEY_ID, user.text());
      Assertions.assertArrayEquals(new byte[] { 4 }, user.bytes());
      Assertions.assertTrue(user.atEnd());
    }
  }

  @Test
  public void nameTruncationKeepsUtf8CharactersAndTheCompleteUppercaseIndex() {
    byte[] id = { (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x01, 0x23, 0x45, 0x67, (byte) 0x89 };
    System.arraycopy(id, 0, this.id, 0, id.length);

    for (int prefix : new int[] { 42, 43, 44, 45 }) {
      String start = "a".repeat(prefix);
      String name = start + "\u8d26\u6237";
      Credential credential = read(record(new int[] { 1, 2, 3, 4, 5, 6, 8, 9, 10 }, name), null);
      CBORReader user = user(credential, true);

      Assertions.assertEquals(2, user.map());
      user.text();
      user.bytes();
      Assertions.assertArrayEquals(Constants.KEY_NAME, user.text());
      byte[] result = user.text();
      Assertions.assertTrue(result.length <= 64);
      Assertions.assertEquals(
        start + (prefix == 42 ? "\u8d26" : "") + " [ABCDEF0123456789]",
        new String(result, StandardCharsets.UTF_8)
      );
      Assertions.assertTrue(user.atEnd());
    }
  }

  @Test
  public void emptyNamesUseTheIndexWithoutALeadingSpace() {
    Credential credential = read(record(new int[] { 1, 2, 3, 4, 5, 6, 8, 9, 10 }, ""), null);
    CBORReader user = user(credential, true);

    Assertions.assertEquals(2, user.map());
    user.text();
    user.bytes();
    Assertions.assertArrayEquals(Constants.KEY_NAME, user.text());
    Assertions.assertEquals("[0101010101010101]", text(user));
    Assertions.assertTrue(user.atEnd());
  }

  @Test
  public void everyRequiredFieldMustBePresent() {
    for (int missing : REQUIRED) {
      int[] fields = Arrays.stream(REQUIRED)
        .filter(field -> field != missing)
        .toArray();
      assertStatus(CTAP.MISSING_PARAMETER, record(fields, null));
    }
  }

  @Test
  public void duplicateKnownFieldsAreRejected() {
    for (int duplicate = 1; duplicate <= 10; duplicate++) {
      int[] fields = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, duplicate };
      assertStatus(CTAP.INVALID_CBOR, record(fields, "name"));
    }
  }

  @Test
  public void scopeMustContainExactly32Bytes() {
    byte[] encoded = record(REQUIRED, null);
    byte[] shortened = Arrays.copyOf(encoded, encoded.length - 1);
    shortened[encoded.length - 33] = 31;

    assertStatus(CTAP.INVALID_LENGTH, shortened);
  }

  @Test
  public void missingOptionalFieldsDoNotRetainPreviousNames() {
    Credential credential = read(record(new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, "name"), null);
    Assertions.assertSame(credential, read(record(REQUIRED, null), credential));
    byte[] output = new byte[128];
    CBORBufferWriter writer = new CBORBufferWriter(output, (short) 0, CTAP.LIMIT_EXCEEDED);
    credential.writeUser(writer, true);
    CBORReader reader = new CBORReader(output, (short) 0, writer.getLength());
    Assertions.assertEquals(2, reader.map());
    Assertions.assertArrayEquals(Constants.KEY_ID, reader.text());
    Assertions.assertArrayEquals(new byte[] { 4 }, reader.bytes());
    Assertions.assertArrayEquals(Constants.KEY_DISPLAY_NAME, reader.text());
    Assertions.assertEquals(
      "[0101010101010101]",
      new String(reader.text(), StandardCharsets.UTF_8)
    );
    Assertions.assertTrue(reader.atEnd());
  }

  @Test
  public void malformedStoredValuesAndTrailingDataAreRejected() {
    byte[] encoded = record(REQUIRED, null);
    byte[] version = encoded.clone();
    version[2] = 2;
    assertStatus(CTAP.OTHER, version);
    assertStatus(CTAP.OTHER, Arrays.copyOf(encoded, encoded.length + 1));
    Assertions.assertThrows(ISOException.class, () ->
      read(Arrays.copyOf(encoded, encoded.length - 1), null)
    );

    byte[] invalidText = record(new int[] { 1, 2, 3, 4, 5, 6, 8, 9, 10 }, "x");
    for (int offset = 0; offset < invalidText.length - 2; offset++) {
      if (
        invalidText[offset] == 6 &&
        invalidText[offset + 1] == 0x61 &&
        invalidText[offset + 2] == 'x'
      ) {
        invalidText[offset + 2] = (byte) 0x80;
        break;
      }
    }
    assertStatus(CTAP.INVALID_CBOR, invalidText);
  }

  private Credential read(byte[] encoded, Credential reusable) {
    return Credential.read(encoded, (short) 0, (short) encoded.length, reusable);
  }

  private CBORReader user(Credential credential, boolean verified) {
    byte[] output = new byte[256];
    CBORBufferWriter writer = new CBORBufferWriter(output, (short) 0, CTAP.LIMIT_EXCEEDED);
    credential.writeUser(writer, verified);

    return new CBORReader(output, (short) 0, writer.getLength());
  }

  private static String text(CBORReader reader) {
    return new String(reader.text(), StandardCharsets.UTF_8);
  }

  private void assertStatus(short status, byte[] encoded) {
    ISOException error = Assertions.assertThrows(ISOException.class, () -> read(encoded, null));
    Assertions.assertEquals(status, error.getReason());
  }

  private byte[] record(int[] order, String name) {
    byte[] output = new byte[512];
    CBORBufferWriter writer = new CBORBufferWriter(output, (short) 0, CTAP.LIMIT_EXCEEDED);
    writer.map((short) order.length);
    for (int field : order) {
      writer.integer((short) field);
      switch (field) {
        case 1:
          writer.integer((short) 1);
          break;
        case 2:
          writer.bytes(id);
          break;
        case 3:
          writer.bytes(rpHash);
          break;
        case 4:
          writer.text("example.test".getBytes(StandardCharsets.UTF_8));
          break;
        case 5:
          writer.bytes(new byte[] { 4 });
          break;
        case 6:
        case 7:
          writer.text(name.getBytes(StandardCharsets.UTF_8));
          break;
        case 8:
          writer.bool(true);
          break;
        case 9:
          writer.bytes(publicKey);
          break;
        case 10:
          writer.bytes(scope);
          break;
        default:
          writer.array((short) 2);
          writer.integer((short) -7);
          writer.text("unknown".getBytes(StandardCharsets.UTF_8));
      }
    }
    return Arrays.copyOf(output, writer.getLength());
  }

  private static byte[] filled(int length, int value) {
    byte[] bytes = new byte[length];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }

  public static class TestApplet extends Applet {

    public static void install(byte[] bytes, short offset, byte length) {
      new TestApplet().register();
    }

    @Override
    public void process(APDU apdu) {}
  }
}
