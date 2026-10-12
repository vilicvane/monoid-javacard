package monoidsafe;

import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.util.ArrayList;
import java.util.List;
import javacard.framework.AID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class MonoidSafeAppletTest {

  private static final AID SAFE_AID = AIDUtil.create("f06d6f6e6f696400010000");

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

  private void checkRemoval(int capacity, int removedPosition) {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");

    SimulatorRuntime runtime = new SimulatorRuntime();
    CardSimulator simulator = new CardSimulator(runtime);
    simulator.installApplet(SAFE_AID, MonoidSafeApplet.class);
    Assertions.assertTrue(simulator.selectApplet(SAFE_AID));
    MonoidSafeApplet safe = (MonoidSafeApplet) runtime.lookupApplet(SAFE_AID).getApplet();

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

  private void assertItems(MonoidSafeApplet safe, List<byte[]> indexes, List<byte[]> values) {
    Object[] items = safe.list((short) 0);
    Assertions.assertEquals(indexes.size(), items.length);

    for (int position = 0; position < items.length; position++) {
      SafeItemShareable item = (SafeItemShareable) items[position];

      Assertions.assertArrayEquals(indexes.get(position), item.getIndex());
      Assertions.assertArrayEquals(values.get(position), item.getData());
      Assertions.assertSame(item, safe.get(indexes.get(position)));
    }
  }
}
