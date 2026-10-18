package monoidsafe;

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
import monoidsafeidentity.MonoidSafeIdentityApplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.SafeCallerApplet;

public class MonoidSafeAppletTest {

  private static final AID IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_IDENTITY_AID}}"
    "f06d6f6e6f696400010000"
  );
  private static final AID SAFE_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_AID}}"
    "f06d6f6e6f696401010000"
  );
  private static final AID CALLER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID_WITHOUT_VERSION}}0001"
    "f06d6f6e6f696402010001"
  );

  private static final byte[] PIN = { 1, 2, 3, 4, 5, 6 };

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
    SafeShareable safe = initializeSafe();
    byte[] data = { (byte) 0x80, 0, 2 };
    byte[] first = createItem(
      safe,
      (short) 0x0401,
      1,
      new byte[] { (byte) 0x80, 0, (byte) 0xFF },
      new byte[] { 1 }
    );
    byte[] second = createItem(
      safe,
      (short) 0x0402,
      2,
      new byte[] { (byte) 0x80, 0, (byte) 0xFF },
      new byte[] { 2 }
    );
    createItem(safe, (short) 0x0401, 3, new byte[] { (byte) 0x80, 1, (byte) 0xFF }, data);
    byte[] fourth = createItem(
      safe,
      (short) 0x0501,
      4,
      new byte[] { (byte) 0x80, 0, (byte) 0xFF },
      new byte[] { 4 }
    );
    createItem(safe, (short) 0x0401, 5, new byte[] { 0, (byte) 0x80, 0 }, data);
    createItem(safe, (short) 0x0401, 6, null, data);
    byte[] key = { (byte) 0x80, 0 };

    assertListedItems(safe, (short) 0, key, first, second, fourth);
    assertListedItems(safe, (short) 0x0400, key, first, second);
    assertListedItems(safe, (short) 0x0401, key, first);
    assertListedItems(safe, (short) 0x0501, key, fourth);
    assertListedItems(safe, (short) 0x0600, key);
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
    SafeShareable safe = initializeSafe();
    byte[] data = { (byte) 0x80, 0 };
    byte[] absent = createItem(safe, (short) 0x0401, 1, null, data);
    byte[] empty = createItem(safe, (short) 0x0401, 2, new byte[0], data);
    byte[] value = createItem(safe, (short) 0x0402, 3, data, new byte[0]);

    Assertions.assertEquals(3, safe.list((short) 0).getCount());
    Assertions.assertNull(safe.get(absent).getKey());
    Assertions.assertArrayEquals(new byte[0], safe.get(empty).getKey());
    assertListedItems(safe, (short) 0, null, absent, empty, value);
    assertListedItems(safe, (short) 0, new byte[0], absent, empty, value);
    assertListedItems(safe, (short) 0x0401, null, absent, empty);
    assertListedItems(safe, (short) 0x0401, new byte[0], absent, empty);
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80 }, value);
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80, 0 }, value);
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80, 0, 0 });
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80, 1 });
  }

  @Test
  public void copiesCreationKeysAndPreservesThemWhenDataChanges() {
    SafeShareable safe = initializeSafe();
    byte[] key = { 1, 2 };
    byte[] data = { 3, 4 };
    byte[] index = createItem(safe, (short) 0x0401, 1, key, data);
    SafeItemShareable item = safe.get(index);
    key[0] = 9;
    byte[] returnedKey = item.getKey();
    returnedKey[0] = 8;
    Assertions.assertArrayEquals(new byte[] { 1, 2 }, item.getKey());

    byte[] replacement = { (byte) 0xFF, 0 };
    item.setData(replacement);
    Assertions.assertArrayEquals(new byte[] { 1, 2 }, item.getKey());
    Assertions.assertArrayEquals(replacement, item.getData());
    assertListedItems(safe, (short) 0, new byte[] { 1 }, index);
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0xFF });
  }

  @Test
  public void iteratorsKeepIndependentCursorsAndCopyTheKeyPrefix() {
    SafeShareable safe = initializeSafe();
    byte[] first = createItem(safe, (short) 0x1000, 1, new byte[] { 1, 2 }, new byte[] { 1 });
    byte[] second = createItem(safe, (short) 0x1000, 2, new byte[] { 2, 3 }, new byte[] { 2 });
    byte[] third = createItem(safe, (short) 0x1000, 3, new byte[] { 1, 4 }, new byte[] { 3 });
    byte[] prefix = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) 1);
    prefix[0] = 1;
    SafeItemIteratorShareable filtered = safe.list((short) 0, prefix);
    prefix[0] = 2;
    SafeItemIteratorShareable all = safe.list((short) 0);

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
    SafeShareable safe = initializeSafe();
    byte[] absent = createItem(safe, (short) 0x1002, 1, null, new byte[] { 1 });
    byte[] empty = createItem(safe, (short) 0x1002, 2, new byte[0], new byte[] { 2 });
    safe.get(empty).setAlias(new byte[0]);
    byte[] index = createItem(safe, (short) 0x1001, 3, new byte[] { 1, 2, 3 }, new byte[] { 3 });
    SafeItemShareable item = safe.get(index);
    item.setAlias(new byte[] { 4, 5, 6, 7 });

    Assertions.assertEquals(
      SafeShareable.INDEX_LENGTH + 7,
      safe.list((short) 0).getMaxMetadataLength()
    );
    Assertions.assertEquals(
      SafeShareable.INDEX_LENGTH,
      safe.list((short) 0x1002).getMaxMetadataLength()
    );
    Assertions.assertEquals(
      SafeShareable.INDEX_LENGTH + 7,
      safe.list((short) 0x1001).getMaxMetadataLength()
    );
    SafeItemIteratorShareable missing = safe.list((short) 0, new byte[] { 9 });
    Assertions.assertEquals(0, missing.getCount());
    Assertions.assertEquals(0, missing.getMaxMetadataLength());
    Assertions.assertNull(missing.next());

    byte[] destination = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      (short) (SafeShareable.INDEX_LENGTH + 11)
    );
    Arrays.fill(destination, (byte) 0x7E);
    short offset = 2;
    Assertions.assertEquals(SafeShareable.INDEX_LENGTH, item.getIndex(destination, offset));
    offset += SafeShareable.INDEX_LENGTH;
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
    SafeShareable safe = initializeSafe();
    byte[] index = createItem(safe, (short) 0x1001, 1, null, new byte[] { 1, 2 });
    SafeItemShareable item = safe.get(index);
    Assertions.assertFalse(item.isSecret());
    item.setSecret(true);
    Assertions.assertTrue(item.isSecret());

    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      item.setSecret(false)
    );
    Assertions.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, exception.getReason());
    Assertions.assertTrue(item.isSecret());
    Assertions.assertArrayEquals(new byte[] { 1, 2 }, item.getData());

    item.setData(new byte[] { 3 });
    Assertions.assertTrue(item.isSecret());
    byte[] replacement = { 4, 5, 6 };
    item.setData(replacement, false);
    replacement[0] = 0;
    Assertions.assertFalse(item.isSecret());
    Assertions.assertArrayEquals(new byte[] { 4, 5, 6 }, item.getData());
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
  public void prefixListingAndReturnedItemsRequireSessionAuthorization() {
    SafeShareable safe = initializeSafe();
    byte[] key = { (byte) 0x80, 0 };
    byte[] data = { 1, 2 };
    byte[] itemIndex = createItem(safe, (short) 0x0401, 1, key, data);
    SafeItemIteratorShareable iterator = safe.list((short) 0, key);
    SafeItemShareable item = iterator.next();
    Assertions.assertArrayEquals(key, item.getKey());
    Assertions.assertArrayEquals(data, item.getData());

    byte[] wrongPIN = { 6, 5, 4, 3, 2, 1 };
    Assertions.assertFalse(safe.checkPIN(wrongPIN, (short) 0, (byte) wrongPIN.length));

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
    byte[] destination = new byte[SafeShareable.INDEX_LENGTH];
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
      item.setData(new byte[] { 1 }, false)
    );
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    exception = Assertions.assertThrows(ISOException.class, () -> item.exportData(new byte[65]));
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    exception = Assertions.assertThrows(ISOException.class, () ->
      safe.importItem(itemIndex, null, null, new byte[65], new byte[144])
    );
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
  }

  private SafeShareable initializeSafe() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");

    ShareableSimulatorRuntime runtime = new ShareableSimulatorRuntime();
    CardSimulator simulator = new CardSimulator(runtime);
    simulator.installApplet(IDENTITY_AID, MonoidSafeIdentityApplet.class);
    simulator.installApplet(SAFE_AID, MonoidSafeApplet.class);
    simulator.installApplet(CALLER_AID, SafeCallerApplet.class);
    Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
    SafeShareable safe = (SafeShareable) runtime.getSharedObject(SAFE_AID, (byte) 0);
    safe.updatePIN(PIN, (short) 0, (byte) PIN.length);
    Assertions.assertTrue(safe.checkPIN(PIN, (short) 0, (byte) PIN.length));

    return safe;
  }

  private byte[] createItem(SafeShareable safe, short type, int id, byte[] key, byte[] data) {
    byte[] index = new byte[SafeShareable.INDEX_LENGTH];
    index[0] = (byte) (type >> 8);
    index[1] = (byte) type;
    index[index.length - 1] = (byte) id;
    Assertions.assertNotNull(safe.create(index, key, null, data, false));

    return index;
  }

  private void assertListedItems(SafeShareable safe, short type, byte[] key, byte[]... indexes) {
    SafeItemIteratorShareable items = safe.list(type, key);
    Assertions.assertEquals(indexes.length, items.getCount());

    for (int position = 0; position < indexes.length; position++) {
      SafeItemShareable item = items.next();

      Assertions.assertNotNull(item);
      Assertions.assertArrayEquals(indexes[position], item.getIndex());
      Assertions.assertArrayEquals(safe.get(indexes[position]).getKey(), item.getKey());
      Assertions.assertArrayEquals(safe.get(indexes[position]).getData(), item.getData());
    }

    Assertions.assertNull(items.next());
  }

  private void checkRemoval(int capacity, int removedPosition) {
    SafeShareable safe = initializeSafe();
    List<byte[]> indexes = new ArrayList<>();
    List<byte[]> values = new ArrayList<>();

    for (int item = 0; item < capacity; item++) {
      byte[] index = new byte[SafeShareable.INDEX_LENGTH];
      index[0] = 0x10;
      index[index.length - 1] = (byte) item;
      byte[] data = { (byte) item };

      Assertions.assertNotNull(safe.create(index, null, null, data, false));
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
    Assertions.assertNotNull(safe.create(removedIndex, null, null, replacement, false));
    indexes.add(removedIndex);
    values.add(replacement);

    assertItems(safe, indexes, values);
  }

  private void assertItems(SafeShareable safe, List<byte[]> indexes, List<byte[]> values) {
    SafeItemIteratorShareable items = safe.list((short) 0);
    Assertions.assertEquals(indexes.size(), items.getCount());

    for (int position = 0; position < indexes.size(); position++) {
      SafeItemShareable item = items.next();

      Assertions.assertNotNull(item);
      Assertions.assertArrayEquals(indexes.get(position), item.getIndex());
      Assertions.assertArrayEquals(values.get(position), item.getData());
      SafeItemShareable found = safe.get(indexes.get(position));
      Assertions.assertNotNull(found);
      Assertions.assertArrayEquals(item.getIndex(), found.getIndex());
      Assertions.assertArrayEquals(item.getData(), found.getData());
    }

    Assertions.assertNull(items.next());
  }
}
