package monoidsafe;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.util.ArrayList;
import java.util.List;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.SafeCallerApplet;
import tests.ShareableSimulatorRuntime;

public class MonoidSafeAppletTest {

  private static final AID SAFE_AID = AIDUtil.create("f06d6f6e6f696400010000");
  private static final AID CALLER_AID = AIDUtil.create("f06d6f6e6f696401010001");

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
  public void listsItemsByBinaryDataPrefixAndTypeInInsertionOrder() {
    SafeShareable safe = initializeSafe();
    byte[] first = createItem(safe, (short) 0x0401, 1, new byte[] { (byte) 0x80, 0, (byte) 0xFF });
    byte[] second = createItem(safe, (short) 0x0402, 2, new byte[] { (byte) 0x80, 0 });
    createItem(safe, (short) 0x0401, 3, new byte[] { (byte) 0x80, 1, (byte) 0xFF });
    byte[] fourth = createItem(safe, (short) 0x0501, 4, new byte[] { (byte) 0x80, 0, 1 });
    createItem(safe, (short) 0x0401, 5, new byte[] { 0, (byte) 0x80, 0 });
    byte[] prefix = { (byte) 0x80, 0 };

    assertListedItems(safe, (short) 0, prefix, first, second, fourth);
    assertListedItems(safe, (short) 0x0400, prefix, first, second);
    assertListedItems(safe, (short) 0x0401, prefix, first);
    assertListedItems(safe, (short) 0x0501, prefix, fourth);
    assertListedItems(safe, (short) 0x0600, prefix);
  }

  @Test
  public void handlesEmptyDataAndPrefixLengthBoundaries() {
    SafeShareable safe = initializeSafe();
    byte[] empty = createItem(safe, (short) 0x0401, 1, new byte[0]);
    byte[] value = createItem(safe, (short) 0x0402, 2, new byte[] { (byte) 0x80, 0 });

    Assertions.assertEquals(2, safe.list((short) 0).length);
    assertListedItems(safe, (short) 0, null, empty, value);
    assertListedItems(safe, (short) 0, new byte[0], empty, value);
    assertListedItems(safe, (short) 0x0401, null, empty);
    assertListedItems(safe, (short) 0x0401, new byte[0], empty);
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80 }, value);
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80, 0 }, value);
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80, 0, 0 });
    assertListedItems(safe, (short) 0, new byte[] { (byte) 0x80, 1 });
  }

  @Test
  public void prefixListingAndReturnedItemsRequireSessionAuthorization() {
    SafeShareable safe = initializeSafe();
    byte[] data = { (byte) 0x80, 0 };
    createItem(safe, (short) 0x0401, 1, data);
    SafeItemShareable item = (SafeItemShareable) safe.list((short) 0, data)[0];
    Assertions.assertArrayEquals(data, item.getData());

    byte[] wrongPIN = { 6, 5, 4, 3, 2, 1 };
    Assertions.assertFalse(safe.checkPIN(wrongPIN, (short) 0, (byte) wrongPIN.length));

    for (byte[] prefix : new byte[][] { null, new byte[0], data, new byte[] { 1 } }) {
      ISOException exception = Assertions.assertThrows(ISOException.class, () ->
        safe.list((short) 0, prefix)
      );
      Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    }

    ISOException exception = Assertions.assertThrows(ISOException.class, item::getData);
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
  }

  private SafeShareable initializeSafe() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");

    ShareableSimulatorRuntime runtime = new ShareableSimulatorRuntime();
    CardSimulator simulator = new CardSimulator(runtime);
    simulator.installApplet(SAFE_AID, MonoidSafeApplet.class);
    simulator.installApplet(CALLER_AID, SafeCallerApplet.class);
    Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
    SafeShareable safe = (SafeShareable) runtime.getSharedObject(SAFE_AID, (byte) 0);
    safe.updatePIN(PIN, (short) 0, (byte) PIN.length);
    Assertions.assertTrue(safe.checkPIN(PIN, (short) 0, (byte) PIN.length));

    return safe;
  }

  private byte[] createItem(SafeShareable safe, short type, int id, byte[] data) {
    byte[] index = new byte[SafeShareable.INDEX_LENGTH];
    index[0] = (byte) (type >> 8);
    index[1] = (byte) type;
    index[index.length - 1] = (byte) id;
    Assertions.assertNotNull(safe.create(index, null, data));

    return index;
  }

  private void assertListedItems(SafeShareable safe, short type, byte[] prefix, byte[]... indexes) {
    Object[] items = safe.list(type, prefix);
    Assertions.assertEquals(indexes.length, items.length);

    for (int position = 0; position < items.length; position++) {
      SafeItemShareable item = (SafeItemShareable) items[position];

      Assertions.assertArrayEquals(indexes[position], item.getIndex());
      Assertions.assertArrayEquals(safe.get(indexes[position]).getData(), item.getData());
    }
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

      Assertions.assertNotNull(safe.create(index, null, data));
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
    Assertions.assertNotNull(safe.create(removedIndex, null, replacement));
    indexes.add(removedIndex);
    values.add(replacement);

    assertItems(safe, indexes, values);
  }

  private void assertItems(SafeShareable safe, List<byte[]> indexes, List<byte[]> values) {
    Object[] items = safe.list((short) 0);
    Assertions.assertEquals(indexes.size(), items.length);

    for (int position = 0; position < items.length; position++) {
      SafeItemShareable item = (SafeItemShareable) items[position];

      Assertions.assertArrayEquals(indexes.get(position), item.getIndex());
      Assertions.assertArrayEquals(values.get(position), item.getData());
      SafeItemShareable found = safe.get(indexes.get(position));
      Assertions.assertNotNull(found);
      Assertions.assertArrayEquals(item.getIndex(), found.getIndex());
      Assertions.assertArrayEquals(item.getData(), found.getData());
    }
  }
}
