package monoid;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.nio.charset.StandardCharsets;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoidsafe.MonoidSafeApplet;
import monoidsafe.SafeShareable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tests.ShareableSimulatorRuntime;

public class CommandItemKeyTest {

  private static final AID MONOID_SAFE_AID = AIDUtil.create("f06d6f6e6f696400010000");
  private static final AID MONOID_AID = AIDUtil.create("f06d6f6e6f696401010000");

  private static final byte[] PIN = "314159".getBytes(StandardCharsets.US_ASCII);

  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    resetAppletState();

    simulator = new CardSimulator(new ShareableSimulatorRuntime());
    simulator.installApplet(MONOID_SAFE_AID, MonoidSafeApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));

    assertSuccess(transmit(0x22, pinRequest(true)));
    assertSuccess(transmit(0x21, pinRequest(false)));
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(MONOID_AID);
    simulator.deleteApplet(MONOID_SAFE_AID);
    resetAppletState();
  }

  @Test
  public void accessPINListsKeyPrefixesWithoutMatchingPrivateData() {
    byte[] firstKey = { (byte) 0x80, 0, (byte) 0xFF };
    byte[] first = create(null, customIndex(1), firstKey, new byte[] { 1 });
    byte[] scalar = new byte[32];
    scalar[31] = 1;
    byte[] secondKey = { (byte) 0x80, 0, (byte) 0xFF };
    byte[] second = create(Safe.TYPE_TEXT_SECP256R1, null, secondKey, scalar);
    byte[] data = { (byte) 0x80, 0, (byte) 0xFF };
    byte[] absent = create(null, customIndex(2), null, data);
    byte[] other = create(null, customIndex(3), new byte[] { (byte) 0x80, 1 }, data);
    byte[] prefix = { (byte) 0x80, 0 };

    Assertions.assertEquals(Command.AUTH_ACCESS, Command.getAuth());
    assertListedItems((short) 0, prefix, first, second);
    assertListedItems(Safe.TYPE_WEIERSTRASS, prefix, second);
    assertListedItems(Safe.TYPE_WEIERSTRASS_SECP256R1, prefix, second);
    assertListedItems((short) 0x1000, prefix, first);
    assertListedItems((short) 0, firstKey, first, second);
    assertListedItems((short) 0, new byte[] { (byte) 0x80, 0, (byte) 0xFF, 0 });
    assertListedItems((short) 0, new byte[] { 1 });
    assertListedItems((short) 0, null, first, second, absent, other);
    assertListedItems((short) 0, new byte[0], first, second, absent, other);
    assertMetadata(first, firstKey);
    assertMetadata(second, secondKey);
    assertMetadata(absent, null);
    assertError(transmit(0x32, indexRequest(second)), MonoidException.CODE_ACCESS_DENIED);
  }

  @Test
  public void preservesCreationKeyWhenOtherFieldsAreUpdated() {
    byte[] key = { 1, 2 };
    byte[] data = { 3, 4 };
    byte[] index = create(null, customIndex(1), key, data);
    byte[] replacement = { (byte) 0xFF, 0 };
    set(index, replacement, null);
    assertMetadata(index, key);
    assertListedItems((short) 0, key, index);
    assertListedItems((short) 0, replacement);

    byte[] replacementData = { 5, 6 };
    set(index, null, replacementData);
    assertMetadata(index, key);

    assertSuccess(transmit(0x21, pinRequest(true)));
    CBORBufferReader reader = assertSuccess(transmit(0x32, indexRequest(index)));
    Assertions.assertArrayEquals(key, reader.requireKey(Text.key).bytes());
    Assertions.assertArrayEquals(replacementData, reader.requireKey(Text.data).bytes());
  }

  @Test
  public void omittedKeysPreserveExistingResponsesAndListStillRequiresAuthorization() {
    byte[] data = { 1, 2 };
    byte[] index = create(null, customIndex(1), null, data);
    assertMetadata(index, null);
    assertListedItems((short) 0, new byte[0], index);
    CBORBufferReader reader = assertSuccess(transmit(0x30, new byte[] { (byte) 0xA0 }));
    Assertions.assertEquals(1, reader.requireKey(Text.items).array());
    Assertions.assertTrue(reader.index((short) 0));
    reader.map();
    Assertions.assertFalse(reader.key(Text.key));
    Assertions.assertFalse(reader.key(Text.data));

    assertSuccess(transmit(0x21, pinRequest(true)));
    reader = assertSuccess(transmit(0x32, indexRequest(index)));
    Assertions.assertFalse(reader.key(Text.key));
    Assertions.assertArrayEquals(data, reader.requireKey(Text.data).bytes());

    simulator.reset();
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    assertError(transmit(0x30, listRequest((short) 0, data)), MonoidException.CODE_UNAUTHORIZED);
  }

  private void resetAppletState() {
    // Separate simulator instances share Java static fields within the test JVM.
    MonoidApplet.version = 0;
    MonoidApplet.safe = null;
    MonoidApplet.safePIN = null;
    MonoidApplet.keystore = null;
  }

  private byte[] pinRequest(boolean safePIN) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (safePIN ? 2 : 1));
    writer.text(Text.pin);
    writer.text(PIN);

    if (safePIN) {
      writer.text(Text.safe);
      writer.bool(true);
    }

    return writer.getDataBuffer();
  }

  private byte[] customIndex(int id) {
    byte[] index = new byte[SafeShareable.INDEX_LENGTH];
    index[0] = 0x10;
    index[index.length - 1] = (byte) id;
    return index;
  }

  private byte[] create(byte[] type, byte[] index, byte[] key, byte[] data) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (key == null ? 2 : 3));

    if (type != null) {
      writer.text(Text.type);
      writer.text(type);
    } else {
      writer.text(Text.index);
      writer.bytes(index);
    }

    if (key != null) {
      writer.text(Text.key);
      writer.bytes(key);
    }

    writer.text(Text.data);
    writer.bytes(data);
    return assertSuccess(transmit(0x34, writer.getDataBuffer())).requireKey(Text.index).bytes();
  }

  private void set(byte[] index, byte[] key, byte[] data) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (1 + (key != null ? 1 : 0) + (data != null ? 1 : 0)));
    writer.text(Text.index);
    writer.bytes(index);

    if (key != null) {
      writer.text(Text.key);
      writer.bytes(key);
    }

    if (data != null) {
      writer.text(Text.data);
      writer.bytes(data);
    }

    assertSuccess(transmit(0x33, writer.getDataBuffer()));
  }

  private byte[] indexRequest(byte[] index) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 1);
    writer.text(Text.index);
    writer.bytes(index);
    return writer.getDataBuffer();
  }

  private byte[] listRequest(short type, byte[] keyPrefix) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) (keyPrefix == null ? 1 : 2));
    writer.text(Text.type);
    writer.integer(type);

    if (keyPrefix != null) {
      writer.text(Text.keyPrefix);
      writer.bytes(keyPrefix);
    }

    return writer.getDataBuffer();
  }

  private void assertListedItems(short type, byte[] keyPrefix, byte[]... indexes) {
    CBORBufferReader reader = assertSuccess(transmit(0x30, listRequest(type, keyPrefix)));
    Assertions.assertEquals(indexes.length, reader.requireKey(Text.items).array());

    for (short position = 0; position < indexes.length; position++) {
      Assertions.assertTrue(reader.index(position));
      reader.map();
      Assertions.assertArrayEquals(indexes[position], reader.requireKey(Text.index).bytes());
      Assertions.assertFalse(reader.key(Text.data));

      if (keyPrefix != null && keyPrefix.length != 0) {
        byte[] key = reader.requireKey(Text.key).bytes();

        for (short offset = 0; offset < keyPrefix.length; offset++) {
          Assertions.assertEquals(keyPrefix[offset], key[offset]);
        }
      }
    }
  }

  private void assertMetadata(byte[] index, byte[] key) {
    CBORBufferReader reader = assertSuccess(transmit(0x31, indexRequest(index)));
    Assertions.assertFalse(reader.key(Text.data));

    if (key != null) {
      Assertions.assertArrayEquals(key, reader.requireKey(Text.key).bytes());
    } else {
      Assertions.assertFalse(reader.key(Text.key));
    }
  }

  private ResponseAPDU transmit(int instruction, byte[] request) {
    return simulator.transmitCommand(new CommandAPDU(0, instruction, 0, 0, request));
  }

  private CBORBufferReader assertSuccess(ResponseAPDU response) {
    Assertions.assertEquals(0x9000, response.getSW());
    CBORBufferReader reader = new CBORBufferReader(response.getData());
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
