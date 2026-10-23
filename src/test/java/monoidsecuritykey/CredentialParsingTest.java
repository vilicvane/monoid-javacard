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

  private static final int[] REQUIRED = { 1, 2, 3, 4, 5, 8, 9 };
  private final byte[] id = filled(32, 1);
  private final byte[] rpHash = filled(32, 2);
  private final byte[] publicKey = filled(65, 3);

  @BeforeEach
  public void initialize() {
    CardSimulator simulator = new CardSimulator();
    simulator.installApplet(AIDUtil.create("f06d6f6e6f69647b01"), TestApplet.class);
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create("f06d6f6e6f69647b01")));
  }

  @Test
  public void fieldsCanAppearInAnyOrderAndUnknownValuesAreSkipped() {
    byte[] encoded = record(new int[] { 9, 6, 2, 42, 8, 5, 3, 7, 4, 1 }, "账户");
    Credential credential = read(encoded, null);
    Assertions.assertTrue(credential.matchesId(id, (short) 0));
    Assertions.assertTrue(credential.matchesRP(rpHash));
    Assertions.assertTrue(credential.matchesPublicKey(publicKey));
    Assertions.assertTrue(credential.resident());
    Assertions.assertEquals(encoded.length, credential.getLength());
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
    for (int duplicate = 1; duplicate <= 9; duplicate++) {
      int[] fields = { 1, 2, 3, 4, 5, 6, 7, 8, 9, duplicate };
      assertStatus(CTAP.INVALID_CBOR, record(fields, "name"));
    }
  }

  @Test
  public void missingOptionalFieldsDoNotRetainPreviousNames() {
    Credential credential = read(record(new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 }, "name"), null);
    Assertions.assertSame(credential, read(record(REQUIRED, null), credential));
    byte[] output = new byte[128];
    CBORBufferWriter writer = new CBORBufferWriter(output, (short) 0, CTAP.LIMIT_EXCEEDED);
    credential.writeUser(writer, true);
    CBORReader reader = new CBORReader(output, (short) 0, writer.getLength());
    Assertions.assertEquals(1, reader.map());
    Assertions.assertArrayEquals(Constants.KEY_ID, reader.text());
    Assertions.assertArrayEquals(new byte[] { 4 }, reader.bytes());
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

    byte[] invalidText = record(new int[] { 1, 2, 3, 4, 5, 6, 8, 9 }, "x");
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
