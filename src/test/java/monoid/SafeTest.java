package monoid;

import static monoid.TestData.read;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import main.ShareableSimulatorRuntime;
import monoididentity.MonoidIdentityApplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SafeTest {

  private CardSimulator simulator;

  private static final AID IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_IDENTITY_AID}}"
    "f06d6f6e6f69640001"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );

  private static final byte[] PIN = { 1, 2, 3, 4, 5, 6 };

  @Test
  public void createsAndReplacesLargeDataThroughBoundedReads() {
    Safe safe = initializeSafe();
    byte[] index = { 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    byte[] original = new byte[2051];

    for (int offset = 0; offset < original.length; offset++) {
      original[offset] = (byte) offset;
    }

    TestData source = new TestData(original);
    SafeItem item = safe.create(index, null, null, source, false);
    Assertions.assertEquals(9, source.readCount);
    SafeDataSource snapshot = item.getData();
    Assertions.assertArrayEquals(original, read(snapshot));
    byte[] range = new byte[23];
    snapshot.read((short) 1023, range, (short) 2, (short) 17);
    Assertions.assertArrayEquals(
      Arrays.copyOfRange(original, 1023, 1040),
      Arrays.copyOfRange(range, 2, 19)
    );
    snapshot.read((short) 255, range, (short) 1, (short) 19);
    Assertions.assertArrayEquals(
      Arrays.copyOfRange(original, 255, 274),
      Arrays.copyOfRange(range, 1, 20)
    );

    byte[] replacement = new byte[1025];
    Arrays.fill(replacement, (byte) 0x5A);
    TestData replacementSource = new TestData(replacement);
    item.setData(replacementSource, true);
    Assertions.assertEquals(5, replacementSource.readCount);
    Assertions.assertTrue(item.isSecret());
    Assertions.assertArrayEquals(replacement, read(item.getData()));
    Arrays.fill(replacement, (byte) 0);
    Assertions.assertEquals((byte) 0x5A, read(item.getData())[0]);
    Assertions.assertArrayEquals(original, read(snapshot));
  }

  @Test
  public void failedSourceReadsLeaveExistingDataAndSecretUnchanged() {
    Safe safe = initializeSafe();
    byte[] index = { 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    TestData failedCreate = failingData();
    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      safe.create(index, null, null, failedCreate, true)
    );
    Assertions.assertEquals(ISO7816.SW_WRONG_DATA, exception.getReason());
    Assertions.assertNull(safe.get(index));

    SafeItem item = safe.create(index, null, null, new TestData(new byte[] { 1 }), false);
    Assertions.assertThrows(ISOException.class, () -> item.setData(failingData()));
    Assertions.assertThrows(ISOException.class, () -> item.setData(failingData(), true));
    Assertions.assertArrayEquals(new byte[] { 1 }, read(item.getData()));
    Assertions.assertFalse(item.isSecret());
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
  }

  @Test
  public void snapshotsCreateMetadataBeforeCallingTheDataSource() {
    Safe safe = initializeSafe();
    byte[] index = { 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    byte[] originalIndex = index.clone();
    byte[] key = { 1, 2 };
    byte[] alias = { 3, 4 };
    TestData source = new TestData(new byte[] { 5 }) {
      @Override
      public short getLength() {
        Arrays.fill(index, (byte) 0);
        Arrays.fill(key, (byte) 0);
        Arrays.fill(alias, (byte) 0);
        return super.getLength();
      }
    };
    SafeItem item = safe.create(index, key, alias, source, false);

    Assertions.assertArrayEquals(originalIndex, item.getIndex());
    Assertions.assertArrayEquals(new byte[] { 1, 2 }, item.getKey());
    Assertions.assertArrayEquals(new byte[] { 3, 4 }, item.getAlias());
    Assertions.assertArrayEquals(new byte[] { 5 }, read(item.getData()));
  }

  @Test
  public void nestedCreationOfTheSameIndexPreservesTheFirstItem() {
    for (boolean createOnRead : new boolean[] { false, true }) {
      Safe safe = initializeSafe();
      byte[] index = { 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
      TestData source = new TestData(new byte[512]) {
        @Override
        public short getLength() {
          if (!createOnRead) {
            createNested();
          }

          return super.getLength();
        }

        @Override
        public void read(short dataOffset, byte[] buffer, short offset, short length) {
          super.read(dataOffset, buffer, offset, length);

          if (createOnRead && dataOffset == 0) {
            createNested();
          }
        }

        private void createNested() {
          Assertions.assertNotNull(
            safe.create(index, new byte[] { 7 }, null, new TestData(new byte[] { 9 }), true)
          );
        }
      };
      Assertions.assertNull(safe.create(index, null, null, source, false));
      Assertions.assertEquals(1, safe.list((short) 0).getCount());
      SafeItem item = safe.get(index);
      Assertions.assertArrayEquals(new byte[] { 7 }, item.getKey());
      Assertions.assertArrayEquals(new byte[] { 9 }, read(item.getData()));
      Assertions.assertTrue(item.isSecret());
    }
  }

  @Test
  public void rechecksAuthorizationBeforePublishingCopiedData() {
    Safe safe = initializeSafe();
    byte[] index = createItem(safe, (short) 0x1000, 1, null, new byte[] { 1 });
    SafeItem item = safe.get(index);
    TestData source = new TestData(new byte[512]) {
      @Override
      public void read(short dataOffset, byte[] buffer, short offset, short length) {
        super.read(dataOffset, buffer, offset, length);

        if (dataOffset == 0) {
          Assertions.assertFalse(safe.checkPIN(new byte[6]));
        }
      }
    };
    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      item.setData(source, true)
    );
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    authenticateStorage(safe);
    Assertions.assertArrayEquals(new byte[] { 1 }, read(item.getData()));
    Assertions.assertFalse(item.isSecret());
  }

  @Test
  public void retainedDataHandlesRequireCurrentSessionAuthorization() {
    Safe safe = initializeSafe();
    byte[] index = createItem(safe, (short) 0x1000, 1, null, new byte[] { 1, 2, 3 });
    SafeItem item = safe.get(index);
    SafeDataSource data = item.getData();
    SafeDataSource encrypted = item.exportData(safe.getPublicKey());
    Assertions.assertFalse(safe.checkPIN(new byte[6]));

    for (SafeDataSource retained : new SafeDataSource[] { data, encrypted }) {
      ISOException exception = Assertions.assertThrows(ISOException.class, retained::getLength);
      Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
      exception = Assertions.assertThrows(ISOException.class, () ->
        retained.read((short) 0, new byte[1], (short) 0, (short) 1)
      );
      Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    }
  }

  @Test
  public void snapshotsImportMetadataBeforeCallingTheDataSource() {
    Safe safe = initializeSafe();
    byte[] index = { 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    byte[] originalIndex = index.clone();
    byte[] key = { 1, 2 };
    byte[] alias = { 3, 4 };
    byte[] publicKey = safe.getPublicKey();
    SafeItem item = safe.create(index, key, alias, new TestData(new byte[] { 5 }), true);
    byte[] encrypted = read(item.exportData(publicKey));
    item.remove();

    TestData source = new TestData(encrypted) {
      @Override
      public short getLength() {
        Arrays.fill(index, (byte) 0);
        Arrays.fill(key, (byte) 0);
        Arrays.fill(alias, (byte) 0);
        Arrays.fill(publicKey, (byte) 0);
        return super.getLength();
      }
    };
    safe.importItem(index, key, alias, publicKey, source);
    SafeItem imported = safe.get(originalIndex);

    Assertions.assertNotNull(imported);
    Assertions.assertArrayEquals(new byte[] { 1, 2 }, imported.getKey());
    Assertions.assertArrayEquals(new byte[] { 3, 4 }, imported.getAlias());
    Assertions.assertArrayEquals(new byte[] { 5 }, read(imported.getData()));
    Assertions.assertEquals(Constants.SAFE_TRUE, imported.getSecretValue());
    Assertions.assertTrue(imported.isSecret());
  }

  private TestData failingData() {
    return new TestData(new byte[1024]) {
      @Override
      public void read(short dataOffset, byte[] buffer, short offset, short length) {
        super.read(dataOffset, buffer, offset, length);

        if (dataOffset >= 256) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
      }
    };
  }

  @Test
  public void removesLastItemAtFullCapacityAndRecreatesIt() {
    for (int capacity : new int[] { 8, 16 }) {
      checkRemoval(capacity, capacity - 1);
    }
  }

  @Test
  public void removesMiddleItemAtFullCapacityAndRecreatesIt() {
    for (int capacity : new int[] { 8, 16 }) {
      checkRemoval(capacity, capacity / 2);
    }
  }

  @Test
  public void listsItemsByBinaryKeyPrefixAndTypeInInsertionOrder() {
    Safe safe = initializeSafe();
    byte[] data = { (byte) 0x80, 0, 2 };
    byte[] first = createItem(
      safe,
      (short) 0x1301,
      1,
      new byte[] { (byte) 0x80, 0, (byte) 0xFF },
      new byte[] { 1 }
    );
    byte[] second = createItem(
      safe,
      (short) 0x1302,
      2,
      new byte[] { (byte) 0x80, 0, (byte) 0xFF },
      new byte[] { 2 }
    );
    createItem(safe, (short) 0x1301, 3, new byte[] { (byte) 0x80, 1, (byte) 0xFF }, data);
    byte[] fourth = createItem(
      safe,
      (short) 0x1401,
      4,
      new byte[] { (byte) 0x80, 0, (byte) 0xFF },
      new byte[] { 4 }
    );
    createItem(safe, (short) 0x1301, 5, new byte[] { 0, (byte) 0x80, 0 }, data);
    createItem(safe, (short) 0x1301, 6, null, data);
    byte[] key = { (byte) 0x80, 0 };

    assertListedItems(safe, (short) 0, key, first, second, fourth);
    assertListedItems(safe, (short) 0x1300, key, first, second);
    assertListedItems(safe, (short) 0x1301, key, first);
    assertListedItems(safe, (short) 0x1401, key, fourth);
    assertListedItems(safe, (short) 0x1600, key);
    assertListedItems(safe, (short) 0, data);
    assertListedItems(
      safe,
      (short) 0,
      new byte[] { (byte) 0x80, 0, (byte) 0xFF },
      first,
      second,
      fourth
    );
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80, 0, (byte) 0xFF, 0 });
  }

  @Test
  public void handlesMissingAndEmptyKeysAndPrefixLengthBoundaries() {
    Safe safe = initializeSafe();
    byte[] data = { (byte) 0x80, 0 };
    byte[] absent = createItem(safe, (short) 0x1301, 1, null, data);
    byte[] empty = createItem(safe, (short) 0x1301, 2, new byte[0], data);
    byte[] value = createItem(safe, (short) 0x1302, 3, data, new byte[0]);

    Assertions.assertEquals(3, safe.list((short) 0).getCount());
    Assertions.assertNull(safe.get(absent).getKey());
    Assertions.assertArrayEquals(new byte[0], safe.get(empty).getKey());
    assertListedItems(safe, (short) 0, null, absent, empty, value);
    assertListedItems(safe, (short) 0, new byte[0], absent, empty, value);
    assertListedItems(safe, (short) 0x1301, null, absent, empty);
    assertListedItems(safe, (short) 0x1301, new byte[0], absent, empty);
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80 }, value);
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80, 0 }, value);
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80, 0, 0 });
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80, 1 });
  }

  @Test
  public void copiesCreationKeysAndPreservesThemWhenDataChanges() {
    Safe safe = initializeSafe();
    byte[] key = { 1, 2 };
    byte[] data = { 3, 4 };
    byte[] index = createItem(safe, (short) 0x1301, 1, key, data);
    SafeItem item = safe.get(index);
    key[0] = 9;
    byte[] returnedKey = item.getKey();
    returnedKey[0] = 8;
    Assertions.assertArrayEquals(new byte[] { 1, 2 }, item.getKey());

    byte[] replacement = { (byte) 0xFF, 0 };
    item.setData(new TestData(replacement));
    Assertions.assertArrayEquals(new byte[] { 1, 2 }, item.getKey());
    Assertions.assertArrayEquals(replacement, read(item.getData()));
    assertListedItems(safe, (short) 0, new byte[] { 1 }, index);
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0xFF });
  }

  @Test
  public void iteratorsKeepIndependentCursorsAndCopyTheKeyPrefix() {
    Safe safe = initializeSafe();
    byte[] first = createItem(safe, (short) 0x1000, 1, new byte[] { 1, 2 }, new byte[] { 1 });
    byte[] second = createItem(safe, (short) 0x1000, 2, new byte[] { 2, 3 }, new byte[] { 2 });
    byte[] third = createItem(safe, (short) 0x1000, 3, new byte[] { 1, 4 }, new byte[] { 3 });
    byte[] prefix = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) 1);
    prefix[0] = 1;
    SafeItemIterator filtered = safe.list((short) 0, prefix);
    prefix[0] = 2;
    SafeItemIterator all = safe.list((short) 0);

    Assertions.assertEquals(2, filtered.getCount());
    Assertions.assertEquals(3, all.getCount());
    Assertions.assertArrayEquals(first, filtered.next().getIndex());
    Assertions.assertArrayEquals(first, all.next().getIndex());
    Assertions.assertArrayEquals(third, filtered.next().getIndex());
    Assertions.assertArrayEquals(second, all.next().getIndex());
    Assertions.assertNull(filtered.next());
    Assertions.assertArrayEquals(third, all.next().getIndex());
    Assertions.assertNull(all.next());
    Assertions.assertNull(filtered.next());
    Assertions.assertEquals(2, filtered.getCount());
  }

  @Test
  public void measuresOnlyMatchingMetadataAndPreservesMissingAndEmptyFields() {
    Safe safe = initializeSafe();
    byte[] absent = createItem(safe, (short) 0x1002, 1, null, new byte[] { 1 });
    byte[] empty = createItem(safe, (short) 0x1002, 2, new byte[0], new byte[] { 2 });
    safe.get(empty).setAlias(new byte[0]);
    byte[] index = createItem(safe, (short) 0x1001, 3, new byte[] { 1, 2, 3 }, new byte[] { 3 });
    SafeItem item = safe.get(index);
    item.setAlias(new byte[] { 4, 5, 6, 7 });

    Assertions.assertEquals(Safe.INDEX_LENGTH + 7, safe.list((short) 0).getMaxMetadataLength());
    Assertions.assertEquals(Safe.INDEX_LENGTH, safe.list((short) 0x1002).getMaxMetadataLength());
    Assertions.assertEquals(
      Safe.INDEX_LENGTH + 7,
      safe.list((short) 0x1001).getMaxMetadataLength()
    );
    SafeItemIterator missing = safe.list((short) 0, new byte[] { 9 });
    Assertions.assertEquals(0, missing.getCount());
    Assertions.assertEquals(0, missing.getMaxMetadataLength());
    Assertions.assertNull(missing.next());

    byte[] destination = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      (short) (Safe.INDEX_LENGTH + 11)
    );
    Arrays.fill(destination, (byte) 0x7E);
    short offset = 2;
    Assertions.assertEquals(Safe.INDEX_LENGTH, item.getIndex(destination, offset));
    offset += Safe.INDEX_LENGTH;
    Assertions.assertEquals(3, item.getKey(destination, offset));
    offset += 3;
    Assertions.assertEquals(4, item.getAlias(destination, offset));
    byte[] expected = new byte[destination.length];
    Arrays.fill(expected, (byte) 0x7E);
    System.arraycopy(index, 0, expected, 2, index.length);
    System.arraycopy(new byte[] { 1, 2, 3, 4, 5, 6, 7 }, 0, expected, index.length + 2, 7);
    Assertions.assertArrayEquals(expected, destination);

    Assertions.assertArrayEquals(index, item.getIndex());
    Assertions.assertArrayEquals(new byte[] { 1, 2, 3 }, item.getKey());
    Assertions.assertArrayEquals(new byte[] { 4, 5, 6, 7 }, item.getAlias());

    Assertions.assertEquals(-1, safe.get(absent).getKey(destination, (short) 0));
    Assertions.assertEquals(-1, safe.get(absent).getAlias(destination, (short) 0));
    Assertions.assertEquals(0, safe.get(empty).getKey(destination, (short) 0));
    Assertions.assertEquals(0, safe.get(empty).getAlias(destination, (short) 0));
    Assertions.assertArrayEquals(expected, destination);
  }

  @Test
  public void secretCanOnlyBeClearedWhenReplacingData() {
    Safe safe = initializeSafe();
    byte[] index = createItem(safe, (short) 0x1001, 1, null, new byte[] { 1, 2 });
    SafeItem item = safe.get(index);
    byte[] originalData = item.getStoredData();
    Assertions.assertFalse(item.isSecret());
    item.setSecret(true);
    Assertions.assertTrue(item.isSecret());
    Assertions.assertSame(originalData, item.getStoredData());

    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      item.setSecret(false)
    );
    Assertions.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, exception.getReason());
    Assertions.assertTrue(item.isSecret());
    Assertions.assertEquals(Constants.SAFE_TRUE, item.getSecretValue());
    Assertions.assertSame(originalData, item.getStoredData());
    Assertions.assertArrayEquals(new byte[] { 1, 2 }, read(item.getData()));

    item.setData(new TestData(new byte[] { 3 }));
    Assertions.assertTrue(item.isSecret());
    byte[] replacement = { 4, 5, 6 };
    item.setData(new TestData(replacement), false);
    replacement[0] = 0;
    Assertions.assertFalse(item.isSecret());
    Assertions.assertArrayEquals(new byte[] { 4, 5, 6 }, read(item.getData()));
  }

  @Test
  public void copiesOnlyTheRequestedPersistentRange() {
    byte[] source = { 1, 2, 3, 4, 5 };
    byte[] copy = Utils.duplicateAsPersistent(source, (short) 2, (short) 2);
    source[2] = 9;
    Assertions.assertArrayEquals(new byte[] { 3, 4 }, copy);
    Assertions.assertArrayEquals(
      new byte[0],
      Utils.duplicateAsPersistent(source, (short) 2, (short) 0)
    );
  }

  @Test
  public void prefixListingAndReturnedItemsRequireAuthorization() {
    Safe safe = initializeSafe();
    byte[] key = { (byte) 0x80, 0 };
    byte[] data = { 1, 2 };
    byte[] itemIndex = createItem(safe, (short) 0x1301, 1, key, data);
    SafeItemIterator iterator = safe.list((short) 0, key);
    SafeItem item = iterator.next();
    Assertions.assertArrayEquals(key, item.getKey());
    Assertions.assertArrayEquals(data, read(item.getData()));

    byte[] wrongPIN = { 6, 5, 4, 3, 2, 1 };
    Assertions.assertFalse(safe.checkPIN(wrongPIN));

    for (byte[] query : new byte[][] { null, new byte[0], key, new byte[] { 1 } }) {
      ISOException exception = Assertions.assertThrows(ISOException.class, () ->
        safe.list((short) 0, query)
      );
      Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    }

    ISOException exception = Assertions.assertThrows(ISOException.class, item::getData);
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    exception = Assertions.assertThrows(ISOException.class, item::getKey);
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    exception = Assertions.assertThrows(ISOException.class, iterator::getCount);
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    exception = Assertions.assertThrows(ISOException.class, iterator::getMaxMetadataLength);
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    exception = Assertions.assertThrows(ISOException.class, iterator::next);
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    byte[] destination = new byte[Safe.INDEX_LENGTH];
    Arrays.fill(destination, (byte) 0x7E);
    exception = Assertions.assertThrows(ISOException.class, () ->
      item.getIndex(destination, (short) 0)
    );
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    exception = Assertions.assertThrows(ISOException.class, () ->
      item.getKey(destination, (short) 0)
    );
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    exception = Assertions.assertThrows(ISOException.class, () ->
      item.getAlias(destination, (short) 0)
    );
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    byte[] untouched = new byte[destination.length];
    Arrays.fill(untouched, (byte) 0x7E);
    Assertions.assertArrayEquals(untouched, destination);
    exception = Assertions.assertThrows(ISOException.class, item::isSecret);
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    exception = Assertions.assertThrows(ISOException.class, () -> item.setSecret(true));
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    exception = Assertions.assertThrows(ISOException.class, () ->
      item.setData(new TestData(new byte[] { 1 }), false)
    );
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    exception = Assertions.assertThrows(ISOException.class, () -> item.exportData(new byte[65]));
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    exception = Assertions.assertThrows(ISOException.class, () ->
      safe.importItem(itemIndex, null, null, new byte[65], new TestData(new byte[144]))
    );
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
  }

  private void authenticateStorage(Safe safe) {
    CBORBufferWriter writer = new CBORBufferWriter();
    writer.map((short) 2);
    writer.text(Text.secret);
    writer.bool(true);
    writer.text(Text.pin);
    writer.text(PIN);
    javax.smartcardio.ResponseAPDU response = simulator.transmitCommand(
      new javax.smartcardio.CommandAPDU(0, 0x21, 0, 0, writer.getDataBuffer())
    );
    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertEquals(Command.AUTH_SECRET, Command.getAuth());
    safe.checkAccess();
  }

  private Safe initializeSafe() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");

    ShareableSimulatorRuntime runtime = new ShareableSimulatorRuntime();
    simulator = new CardSimulator(runtime);
    simulator.installApplet(IDENTITY_AID, MonoidIdentityApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    Safe safe = new Safe();
    safe.initializeIdentity();
    safe.updatePIN(PIN);
    authenticateStorage(safe);

    return safe;
  }

  private byte[] createItem(Safe safe, short type, int id, byte[] key, byte[] data) {
    byte[] index = new byte[Safe.INDEX_LENGTH];
    index[0] = (byte) (type >> 8);
    index[1] = (byte) type;
    index[index.length - 1] = (byte) id;
    Assertions.assertNotNull(safe.create(index, key, null, new TestData(data), false));

    return index;
  }

  private void assertListedItems(Safe safe, short type, byte[] key, byte[]... indexes) {
    SafeItemIterator items = safe.list(type, key);
    Assertions.assertEquals(indexes.length, items.getCount());

    for (int position = 0; position < indexes.length; position++) {
      SafeItem item = items.next();

      Assertions.assertNotNull(item);
      Assertions.assertArrayEquals(indexes[position], item.getIndex());
      Assertions.assertArrayEquals(safe.get(indexes[position]).getKey(), item.getKey());
      Assertions.assertArrayEquals(
        read(safe.get(indexes[position]).getData()),
        read(item.getData())
      );
    }

    Assertions.assertNull(items.next());
  }

  private void checkRemoval(int capacity, int removedPosition) {
    Safe safe = initializeSafe();
    List<byte[]> indexes = new ArrayList<>();
    List<byte[]> values = new ArrayList<>();

    for (int item = 0; item < capacity; item++) {
      byte[] index = new byte[Safe.INDEX_LENGTH];
      index[0] = 0x10;
      index[index.length - 1] = (byte) item;
      byte[] data = { (byte) item };

      Assertions.assertNotNull(safe.create(index, null, null, new TestData(data), false));
      indexes.add(index);
      values.add(data);
    }

    assertItems(safe, indexes, values);

    byte[] removedIndex = indexes.remove(removedPosition);
    values.remove(removedPosition);
    safe.get(removedIndex).remove();

    Assertions.assertNull(safe.get(removedIndex));
    assertItems(safe, indexes, values);

    byte[] replacement = { (byte) 0xA5 };
    Assertions.assertNotNull(
      safe.create(removedIndex, null, null, new TestData(replacement), false)
    );
    indexes.add(removedIndex);
    values.add(replacement);

    assertItems(safe, indexes, values);
  }

  private void assertItems(Safe safe, List<byte[]> indexes, List<byte[]> values) {
    SafeItemIterator items = safe.list((short) 0);
    Assertions.assertEquals(indexes.size(), items.getCount());

    for (int position = 0; position < indexes.size(); position++) {
      SafeItem item = items.next();

      Assertions.assertNotNull(item);
      Assertions.assertArrayEquals(indexes.get(position), item.getIndex());
      Assertions.assertArrayEquals(values.get(position), read(item.getData()));
      SafeItem found = safe.get(indexes.get(position));
      Assertions.assertNotNull(found);
      Assertions.assertArrayEquals(item.getIndex(), found.getIndex());
      Assertions.assertArrayEquals(read(item.getData()), read(found.getData()));
    }

    Assertions.assertNull(items.next());
  }
}
