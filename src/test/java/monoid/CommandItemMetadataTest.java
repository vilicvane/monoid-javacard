package monoid;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoididentity.MonoidIdentityApplet;
import monoidlib.CBORBufferReader;
import monoidlib.CBORBufferWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CommandItemMetadataTest {

  private static final AID MONOID_IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_IDENTITY_AID}}"
    "f06d6f6e6f69640001"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );

  private static final byte[] PIN = "314159".getBytes(StandardCharsets.US_ASCII);

  private static Object[] chunks(CBORBufferWriter writer) {
    try {
      java.lang.reflect.Field field = CBORBufferWriter.class.getDeclaredField("chunks");
      field.setAccessible(true);
      return (Object[]) field.get(writer);
    } catch (ReflectiveOperationException exception) {
      throw new AssertionError(exception);
    }
  }

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    resetAppletState();

    simulator = new CardSimulator(new ShareableSimulatorRuntime());
    simulator.installApplet(MONOID_IDENTITY_AID, MonoidIdentityApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));

    requireSuccess(transmit(0x22, pinRequest(true)));
    requireSuccess(transmit(0x21, pinRequest(false)));
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(MONOID_AID);
    simulator.deleteApplet(MONOID_IDENTITY_AID);
    resetAppletState();
  }

  @Test
  public void accessPINListsMetadataPrefixesWithoutMatchingPrivateData() {
    byte[] firstMetadata = { (byte) 0x80, 0, (byte) 0xFF };
    byte[] first = create(null, customIndex(1), firstMetadata, new byte[] { 1 });
    byte[] scalar = new byte[32];
    scalar[31] = 1;
    byte[] secondMetadata = { (byte) 0x80, 0, (byte) 0xFF };
    byte[] second = create(Safe.TYPE_TEXT_SECP256R1, null, secondMetadata, scalar);
    byte[] data = { (byte) 0x80, 0, (byte) 0xFF };
    byte[] absent = create(null, customIndex(2), null, data);
    byte[] other = create(null, customIndex(3), new byte[] { (byte) 0x80, 1 }, data);
    byte[] prefix = { (byte) 0x80, 0 };

    Assertions.assertEquals(Command.AUTH_ACCESS, Command.getAuth());
    assertListedItems((short) 0, prefix, first, second);
    assertListedItems(Safe.TYPE_WEIERSTRASS, prefix, second);
    assertListedItems(Safe.TYPE_WEIERSTRASS_SECP256R1, prefix, second);
    assertListedItems((short) 0x1000, prefix, first);
    assertListedItems((short) 0, firstMetadata, first, second);
    assertListedItems((short) 0, new byte[] { (byte) 0x80, 0, (byte) 0xFF, 0 });
    assertListedItems((short) 0, new byte[] { 1 });
    assertListedItems((short) 0, null, first, second, absent, other);
    assertListedItems((short) 0, new byte[0], first, second, absent, other);
    assertMetadata(first, firstMetadata);
    assertMetadata(second, secondMetadata);
    assertMetadata(absent, null);
    CBORBufferReader reader = requireSuccess(transmit(0x32, indexRequest(second)));
    Assertions.assertArrayEquals(scalar, reader.requireKey(Text.data).bytes());
  }

  @Test
  public void preservesCreationMetadataWhenOtherFieldsAreUpdated() {
    byte[] metadata = { 1, 2 };
    byte[] data = { 3, 4 };
    byte[] index = create(null, customIndex(1), metadata, data);
    byte[] replacement = { (byte) 0xFF, 0 };
    set(index, replacement, null);
    assertMetadata(index, metadata);
    assertListedItems((short) 0, metadata, index);
    assertListedItems((short) 0, replacement);

    byte[] replacementData = { 5, 6 };
    set(index, null, replacementData);
    assertMetadata(index, metadata);

    requireSuccess(transmit(0x21, pinRequest(true)));
    CBORBufferReader reader = requireSuccess(transmit(0x32, indexRequest(index)));
    Assertions.assertFalse(reader.key(Text.metadata));
    Assertions.assertArrayEquals(replacementData, reader.requireKey(Text.data).bytes());
  }

  @Test
  public void omittedMetadataPreservesExistingResponsesAndListStillRequiresAuthorization() {
    byte[] data = { 1, 2 };
    byte[] index = create(null, customIndex(1), null, data);
    assertMetadata(index, null);
    assertListedItems((short) 0, new byte[0], index);
    CBORBufferReader reader = requireSuccess(transmit(0x30, new byte[] { (byte) 0xA0 }));
    Assertions.assertEquals(1, reader.requireKey(Text.items).array());
    Assertions.assertTrue(reader.index((short) 0));
    reader.map();
    Assertions.assertFalse(reader.key(Text.metadata));
    Assertions.assertFalse(reader.key(Text.data));

    requireSuccess(transmit(0x21, pinRequest(true)));
    reader = requireSuccess(transmit(0x32, indexRequest(index)));
    Assertions.assertFalse(reader.key(Text.metadata));
    Assertions.assertArrayEquals(data, reader.requireKey(Text.data).bytes());

    simulator.reset();
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    assertError(transmit(0x30, listRequest((short) 0, data)), MonoidException.CODE_UNAUTHORIZED);
  }

  @Test
  public void listsManySmallItemsThroughPackedResponsesAndRecoversFromCancellation() {
    byte[][] indexes = new byte[40][];
    byte[][] metadata = new byte[indexes.length][];
    byte[][] aliases = new byte[indexes.length][];
    byte[][] filteredIndexes = new byte[indexes.length / 2][];

    for (int position = 0; position < indexes.length; position++) {
      metadata[position] = new byte[16];
      metadata[position][0] = (byte) (position % 2);
      metadata[position][15] = (byte) position;
      aliases[position] = ("record-" + (position < 10 ? "0" : "") + position).getBytes(
        StandardCharsets.US_ASCII
      );
      indexes[position] = create(
        null,
        customIndex(position + 1),
        metadata[position],
        aliases[position],
        new byte[] { (byte) position }
      );

      if (position % 2 == 0) {
        filteredIndexes[position / 2] = indexes[position];
      }
    }

    ResponseAPDU response = transmit(0x30, listRequest((short) 0, null));
    Assertions.assertEquals(0x6100, response.getSW());
    Assertions.assertTrue(response.getData().length > 0 && response.getData().length <= 256);

    for (Object chunk : chunks(Command.writer)) {
      Assertions.assertNull(chunk);
    }

    CBORBufferReader reader = requireSuccess(response);
    Assertions.assertEquals(indexes.length, reader.requireKey(Text.items).array());

    for (short position = 0; position < indexes.length; position++) {
      Assertions.assertTrue(reader.index(position));
      reader.map();
      Assertions.assertArrayEquals(metadata[position], reader.requireKey(Text.metadata).bytes());
      Assertions.assertArrayEquals(aliases[position], reader.requireKey(Text.alias).text());
      Assertions.assertArrayEquals(indexes[position], reader.requireKey(Text.index).bytes());
      Assertions.assertFalse(reader.requireKey(Text.secret).bool());
      Assertions.assertFalse(reader.key(Text.data));
    }

    Assertions.assertFalse(Command.writer.hasPending());
    assertListedItems((short) 0, new byte[] { 0 }, filteredIndexes);
    Assertions.assertEquals(0x6100, transmit(0x30, listRequest((short) 0, null)).getSW());
    assertMetadata(indexes[0], metadata[0]);
    Assertions.assertFalse(Command.writer.hasPending());
    Assertions.assertEquals(
      0x6985,
      simulator.transmitCommand(new CommandAPDU(0, 0xC0, 0, 0, 256)).getSW()
    );
    assertListedItems((short) 0, null, indexes);
  }

  @Test
  public void listsMissingAndEmptyMetadataWithoutReusingPreviousValues() {
    byte[] withValues = create(
      null,
      customIndex(1),
      new byte[] { 1, 2 },
      new byte[] { 3, 4 },
      new byte[] { 1 }
    );
    byte[] absent = create(null, customIndex(2), null, new byte[] { 2 });
    byte[] empty = create(null, customIndex(3), new byte[0], new byte[0], new byte[] { 3 });
    CBORBufferReader reader = requireSuccess(transmit(0x30, listRequest((short) 0, null)));
    Assertions.assertEquals(3, reader.requireKey(Text.items).array());
    Assertions.assertTrue(reader.index((short) 0));
    reader.map();
    Assertions.assertArrayEquals(withValues, reader.requireKey(Text.index).bytes());
    Assertions.assertArrayEquals(new byte[] { 1, 2 }, reader.requireKey(Text.metadata).bytes());
    Assertions.assertArrayEquals(new byte[] { 3, 4 }, reader.requireKey(Text.alias).text());
    Assertions.assertTrue(reader.index((short) 1));
    reader.map();
    Assertions.assertArrayEquals(absent, reader.requireKey(Text.index).bytes());
    Assertions.assertFalse(reader.key(Text.metadata));
    Assertions.assertFalse(reader.key(Text.alias));
    Assertions.assertTrue(reader.index((short) 2));
    reader.map();
    Assertions.assertArrayEquals(empty, reader.requireKey(Text.index).bytes());
    Assertions.assertArrayEquals(new byte[0], reader.requireKey(Text.metadata).bytes());
    Assertions.assertArrayEquals(new byte[0], reader.requireKey(Text.alias).text());
  }

  @Test
  public void listsMetadataLargerThanTheAPDUBuffer() {
    byte[] metadata = new byte[80];
    byte[] alias = new byte[200];

    for (int position = 0; position < metadata.length; position++) {
      metadata[position] = (byte) position;
    }

    Arrays.fill(alias, (byte) 'a');
    byte[] index = create(null, customIndex(1), metadata, alias, new byte[] { 1 });
    CBORBufferReader reader = requireSuccess(transmit(0x30, listRequest((short) 0, null)));
    Assertions.assertEquals(1, reader.requireKey(Text.items).array());
    Assertions.assertTrue(reader.index((short) 0));
    reader.map();
    Assertions.assertArrayEquals(metadata, reader.requireKey(Text.metadata).bytes());
    Assertions.assertArrayEquals(alias, reader.requireKey(Text.alias).text());
    Assertions.assertArrayEquals(index, reader.requireKey(Text.index).bytes());
  }

  @Test
  public void listsMoreThanTheBufferedResponseLimit() {
    byte[][] indexes = new byte[160][];
    byte[] metadata = new byte[16];
    byte[] alias = "record-00".getBytes(StandardCharsets.US_ASCII);

    for (int position = 0; position < indexes.length; position++) {
      indexes[position] = create(
        null,
        customIndex(position + 1),
        metadata,
        alias,
        new byte[] { (byte) position }
      );
    }

    assertListedItems((short) 0, null, indexes);
  }

  @Test
  public void preservesBorrowedCreateRequestsWhenTheItemTableExpands() {
    // The physical protocol workload starts with one seed and four credentials.
    for (int position = 0; position < 5; position++) {
      create(null, customIndex(position + 1), null, new byte[] { (byte) position });
    }
    requireSuccess(transmit(0x21, pinRequest(true)));
    assertListedItems((short) 0xF203, null);

    byte[] metadata = "apdu-stream".getBytes(StandardCharsets.US_ASCII);
    byte[] data = "APDU fixture data".getBytes(StandardCharsets.US_ASCII);
    byte[][] indexes = new byte[12][];
    byte[][] aliases = new byte[12][];
    for (int position = 0; position < indexes.length; position++) {
      byte[] index = { (byte) 0xF2, 3, 'A', 'P', 'D', 'U', 0, 0, 0, (byte) position };
      byte[] alias = String.format("APDU streaming fixture %02d", position).getBytes(
        StandardCharsets.US_ASCII
      );
      CBORBufferWriter writer = new CBORBufferWriter();
      writer.map((short) 4);
      writer.text(Text.data);
      writer.bytes(data);
      writer.text(Text.metadata);
      writer.bytes(metadata);
      writer.text(Text.alias);
      writer.text(alias);
      writer.text(Text.index);
      writer.bytes(index);
      byte[] request = writer.getDataBuffer();
      Assertions.assertEquals(95, request.length);
      CBORBufferReader reader = requireSuccess(
        simulator.transmitCommand(new CommandAPDU(0, 0x34, 0, 0, request, 256))
      );
      Assertions.assertArrayEquals(index, reader.requireKey(Text.index).bytes());
      indexes[position] = index;
      aliases[position] = alias;
    }

    assertListedItems((short) 0xF203, metadata, indexes);
    for (int position = 0; position < indexes.length; position++) {
      CBORBufferReader reader = requireSuccess(transmit(0x31, indexRequest(indexes[position])));
      Assertions.assertArrayEquals(aliases[position], reader.requireKey(Text.alias).text());
      Assertions.assertArrayEquals(metadata, reader.requireKey(Text.metadata).bytes());
      reader = requireSuccess(transmit(0x32, indexRequest(indexes[position])));
      Assertions.assertArrayEquals(data, reader.requireKey(Text.data).bytes());
    }
  }

  private void resetAppletState() {
    // Separate simulator instances share Java static fields within the test JVM.
    MonoidApplet.safe = null;
    MonoidApplet.keystore = null;
  }

  private byte[] pinRequest(boolean safePIN) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (safePIN ? 2 : 1));
    writer.text(Text.pin);
    writer.text(PIN);

    if (safePIN) {
      writer.text(Text.secret);
      writer.bool(true);
    }

    return writer.getDataBuffer();
  }

  private byte[] customIndex(int id) {
    byte[] index = new byte[Safe.INDEX_LENGTH];
    index[0] = 0x10;
    index[index.length - 1] = (byte) id;
    return index;
  }

  private byte[] create(byte[] type, byte[] index, byte[] metadata, byte[] data) {
    return create(type, index, metadata, null, data);
  }

  private byte[] create(byte[] type, byte[] index, byte[] metadata, byte[] alias, byte[] data) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (2 + (metadata == null ? 0 : 1) + (alias == null ? 0 : 1)));

    if (type != null) {
      writer.text(Text.type);
      writer.text(type);
    } else {
      writer.text(Text.index);
      writer.bytes(index);
    }

    if (metadata != null) {
      writer.text(Text.metadata);
      writer.bytes(metadata);
    }

    if (alias != null) {
      writer.text(Text.alias);
      writer.text(alias);
    }

    writer.text(Text.data);
    writer.bytes(data);
    return requireSuccess(transmit(0x34, writer.getDataBuffer())).requireKey(Text.index).bytes();
  }

  private void set(byte[] index, byte[] metadata, byte[] data) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (1 + (metadata != null ? 1 : 0) + (data != null ? 1 : 0)));
    writer.text(Text.index);
    writer.bytes(index);

    if (metadata != null) {
      writer.text(Text.metadata);
      writer.bytes(metadata);
    }

    if (data != null) {
      writer.text(Text.data);
      writer.bytes(data);
    }

    requireSuccess(transmit(0x33, writer.getDataBuffer()));
  }

  private byte[] indexRequest(byte[] index) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 1);
    writer.text(Text.index);
    writer.bytes(index);
    return writer.getDataBuffer();
  }

  private byte[] listRequest(short type, byte[] metadataPrefix) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (metadataPrefix == null ? 1 : 2));
    writer.text(Text.type);
    writer.integer(type);

    if (metadataPrefix != null) {
      writer.text(Text.metadataPrefix);
      writer.bytes(metadataPrefix);
    }

    return writer.getDataBuffer();
  }

  private void assertListedItems(short type, byte[] metadataPrefix, byte[]... indexes) {
    CBORBufferReader reader = requireSuccess(transmit(0x30, listRequest(type, metadataPrefix)));
    Assertions.assertEquals(indexes.length, reader.requireKey(Text.items).array());

    for (short position = 0; position < indexes.length; position++) {
      Assertions.assertTrue(reader.index(position));
      reader.map();
      Assertions.assertArrayEquals(indexes[position], reader.requireKey(Text.index).bytes());
      Assertions.assertFalse(reader.key(Text.data));

      if (metadataPrefix != null && metadataPrefix.length != 0) {
        byte[] metadata = reader.requireKey(Text.metadata).bytes();

        for (short offset = 0; offset < metadataPrefix.length; offset++) {
          Assertions.assertEquals(metadataPrefix[offset], metadata[offset]);
        }
      }
    }
  }

  private void assertMetadata(byte[] index, byte[] metadata) {
    CBORBufferReader reader = requireSuccess(transmit(0x31, indexRequest(index)));
    Assertions.assertFalse(reader.key(Text.data));

    if (metadata != null) {
      Assertions.assertArrayEquals(metadata, reader.requireKey(Text.metadata).bytes());
    } else {
      Assertions.assertFalse(reader.key(Text.metadata));
    }
  }

  private ResponseAPDU transmit(int instruction, byte[] request) {
    if (request.length <= 255) {
      return simulator.transmitCommand(new CommandAPDU(0, instruction, 0, 0, request));
    }

    int offset = 0;

    while (request.length - offset > 255) {
      ResponseAPDU response = simulator.transmitCommand(
        new CommandAPDU(
          offset == 0 ? 0x90 : 0xB0,
          instruction,
          0,
          0,
          Arrays.copyOfRange(request, offset, offset + 255)
        )
      );
      Assertions.assertEquals(0x9000, response.getSW());
      offset += 255;
    }

    return simulator.transmitCommand(
      new CommandAPDU(0xA0, instruction, 0, 0, Arrays.copyOfRange(request, offset, request.length))
    );
  }

  private CBORBufferReader requireSuccess(ResponseAPDU response) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    while (true) {
      byte[] data = response.getData();
      output.write(data, 0, data.length);

      if (response.getSW1() != 0x61) {
        break;
      }

      Assertions.assertTrue(data.length > 0 && data.length <= 256);
      response = simulator.transmitCommand(new CommandAPDU(0, 0xC0, 0, 0, 256));
    }

    Assertions.assertEquals(0x9000, response.getSW());
    CBORBufferReader reader = new CBORBufferReader(output.toByteArray());
    reader.map();

    if (reader.key(Text.error)) {
      reader.map();
      Assertions.fail(new String(reader.requireKey(Text.code).text(), StandardCharsets.US_ASCII));
    }

    return reader;
  }

  private void assertError(ResponseAPDU response, byte[] code) {
    Assertions.assertEquals(0x9000, response.getSW());
    CBORBufferReader reader = new CBORBufferReader(response.getData());
    reader.map();
    reader.requireKey(Text.error).map();
    Assertions.assertArrayEquals(code, reader.requireKey(Text.code).text());
  }
}
