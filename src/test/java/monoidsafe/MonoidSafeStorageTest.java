package monoidsafe;

import static monoidsafe.TestData.read;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import main.ShareableSimulatorRuntime;
import monoidsafeidentity.MonoidSafeIdentityApplet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import tests.SafeCallerApplet;

/** Tests decisions from controlled memory reports, not allocator or garbage-collection behavior. */
public class MonoidSafeStorageTest {

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

  private StorageRuntime runtime;
  private CardSimulator simulator;
  private SafeShareable safe;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    runtime = new StorageRuntime();
    simulator = new CardSimulator(runtime);
    simulator.installApplet(IDENTITY_AID, MonoidSafeIdentityApplet.class);
    simulator.installApplet(SAFE_AID, MonoidSafeApplet.class);
    simulator.installApplet(CALLER_AID, SafeCallerApplet.class);
    Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
    safe = (SafeShareable) runtime.getSharedObject(SAFE_AID, (byte) 0);
    safe.updatePIN(PIN, (short) 0, (byte) PIN.length);
    Assertions.assertTrue(safe.checkPIN(PIN, (short) 0, (byte) PIN.length));
  }

  @AfterEach
  public void clear() {
    simulator.deleteApplet(CALLER_AID);
    simulator.deleteApplet(SAFE_AID);
    simulator.deleteApplet(IDENTITY_AID);
  }

  @Test
  public void includesTheEstimatedWriteLengthInTheThreshold() {
    // The fixture stores a ten-byte index, a one-byte alias and one byte of data.
    for (int available : new int[] { 0, 4095, 4096 }) {
      runtime.report(available);
      assertStorageFailure(() -> create(1));
      Assertions.assertEquals(1, runtime.memoryChecks);
      Assertions.assertNull(safe.get(index(1)));
    }

    runtime.report(4107, 4096);
    assertStorageFailure(() -> create(1));
    Assertions.assertEquals(2, runtime.memoryChecks);
    Assertions.assertNull(safe.get(index(1)));

    for (int available : new int[] { 4108, 32767, 32768, 65535 }) {
      runtime.report(available, available - 11, 0);
      SafeItemShareable item = create(available);
      Assertions.assertNotNull(item);
      Assertions.assertEquals(2, runtime.memoryChecks);
      item.remove();
    }
  }

  @Test
  public void includesTheWholeExpandedItemTableInTheEstimate() {
    for (int id = 1; id <= 8; id++) {
      create(id);
    }

    for (int attempt = 0; attempt < 3; attempt++) {
      // Growing from eight to sixteen entries needs a new 32-byte reference array.
      runtime.report(4139, 4128);
      assertStorageFailure(() -> create(9));
      Assertions.assertEquals(2, runtime.memoryChecks);
      Assertions.assertEquals(8, safe.list((short) 0).getCount());
      Assertions.assertNull(safe.get(index(9)));

      for (int id = 1; id <= 8; id++) {
        Assertions.assertArrayEquals(new byte[] { (byte) id }, read(safe.get(index(id)).getData()));
      }
    }

    runtime.report(4140, 4129, 4128, 0);
    Assertions.assertNotNull(create(9));
    Assertions.assertEquals(3, runtime.memoryChecks);
    Assertions.assertEquals(9, safe.list((short) 0).getCount());
  }

  @Test
  public void checksTableGrowthIntroducedByADataCallbackBeforePublishing() {
    for (int id = 1; id <= 7; id++) {
      create(id);
    }

    TestData source = new TestData(new byte[] { 9 }) {
      @Override
      public void read(short dataOffset, byte[] buffer, short offset, short length) {
        super.read(dataOffset, buffer, offset, length);
        Assertions.assertNotNull(create(8));
        runtime.report(4127);
      }
    };
    assertStorageFailure(() -> safe.create(index(9), null, null, source, false));
    Assertions.assertEquals(1, runtime.memoryChecks);
    Assertions.assertEquals(8, safe.list((short) 0).getCount());
    Assertions.assertArrayEquals(new byte[] { 8 }, read(safe.get(index(8)).getData()));
    Assertions.assertNull(safe.get(index(9)));

    runtime.report(32767);
    Assertions.assertNotNull(create(9));
    Assertions.assertEquals(9, safe.list((short) 0).getCount());
  }

  @Test
  public void rejectedReplacementsPreserveDataSecretAndAlias() {
    SafeItemShareable item = create(1);

    for (int available : new int[] { 4095, 4096, 4097 }) {
      runtime.report(available);
      assertStorageFailure(() -> item.setData(new TestData(new byte[] { 2, 3 })));
      Assertions.assertEquals(1, runtime.memoryChecks);
      Assertions.assertArrayEquals(new byte[] { 1 }, read(item.getData()));

      runtime.report(available);
      assertStorageFailure(() -> item.setData(new TestData(new byte[] { 2, 3 }), true));
      Assertions.assertEquals(1, runtime.memoryChecks);
      Assertions.assertArrayEquals(new byte[] { 1 }, read(item.getData()));
      Assertions.assertFalse(item.isSecret());

      runtime.report(available);
      assertStorageFailure(() -> item.setAlias(new byte[] { 4, 5 }));
      Assertions.assertEquals(1, runtime.memoryChecks);
      Assertions.assertArrayEquals(new byte[] { 7 }, item.getAlias());
    }

    runtime.report(4098, 0);
    item.setData(new TestData(new byte[] { 2, 3 }), true);
    Assertions.assertEquals(1, runtime.memoryChecks);
    runtime.report(4098, 0);
    item.setAlias(new byte[] { 4, 5 });
    Assertions.assertEquals(1, runtime.memoryChecks);
    Assertions.assertArrayEquals(new byte[] { 2, 3 }, read(item.getData()));
    Assertions.assertTrue(item.isSecret());
    Assertions.assertArrayEquals(new byte[] { 4, 5 }, item.getAlias());
  }

  @Test
  public void preservesReadsRemovalAndNonAllocatingUpdatesAtLowSpace() {
    SafeItemShareable item = create(1);
    runtime.report(0);

    SafeItemIteratorShareable items = safe.list((short) 0);
    Assertions.assertEquals(1, items.getCount());
    Assertions.assertArrayEquals(index(1), items.next().getIndex());
    Assertions.assertArrayEquals(new byte[] { 1 }, read(safe.get(index(1)).getData()));
    item.setSecret(true);
    item.setAlias(null);
    Assertions.assertTrue(item.isSecret());
    Assertions.assertNull(item.getAlias());
    Assertions.assertNull(create(1));
    item.remove();
    Assertions.assertEquals(0, safe.list((short) 0).getCount());
    Assertions.assertEquals(0, runtime.memoryChecks);
  }

  @Test
  public void importUsesTheSameGuardAndPreservesDuplicateImport() {
    SafeItemShareable item = create(1);
    byte[] publicKey = safe.getPublicKey();
    SafeDataShareable envelope = item.exportData(publicKey);
    item.remove();

    for (int available : new int[] { 4095, 4107 }) {
      runtime.report(available);
      assertStorageFailure(() ->
        safe.importItem(index(1), null, new byte[] { 7 }, publicKey, envelope)
      );
      Assertions.assertEquals(1, runtime.memoryChecks);
      Assertions.assertNull(safe.get(index(1)));
    }

    runtime.report(4108, 0);
    safe.importItem(index(1), null, new byte[] { 7 }, publicKey, envelope);
    Assertions.assertEquals(1, runtime.memoryChecks);
    Assertions.assertArrayEquals(new byte[] { 1 }, read(safe.get(index(1)).getData()));

    runtime.report(0);
    safe.importItem(index(1), null, new byte[] { 7 }, publicKey, envelope);
    Assertions.assertEquals(0, runtime.memoryChecks);
    Assertions.assertEquals(1, safe.list((short) 0).getCount());
  }

  @Test
  public void authorizationIsCheckedBeforeStorage() {
    runtime.report(0);
    Assertions.assertFalse(safe.checkPIN(new byte[6], (short) 0, (byte) 6));
    ISOException exception = Assertions.assertThrows(ISOException.class, () -> create(1));
    Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
    Assertions.assertEquals(0, runtime.memoryChecks);
  }

  private SafeItemShareable create(int id) {
    return safe.create(
      index(id),
      null,
      new byte[] { 7 },
      new TestData(new byte[] { (byte) id }),
      false
    );
  }

  private byte[] index(int id) {
    byte[] index = new byte[SafeShareable.INDEX_LENGTH];
    index[0] = 0x10;
    index[index.length - 2] = (byte) (id >> 8);
    index[index.length - 1] = (byte) id;
    return index;
  }

  private void assertStorageFailure(Executable operation) {
    ISOException exception = Assertions.assertThrows(ISOException.class, operation);
    Assertions.assertEquals(ISO7816.SW_FILE_FULL, exception.getReason());
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
    Assertions.assertTrue(runtime.deletionRequests > 0);
  }

  private static class StorageRuntime extends ShareableSimulatorRuntime {

    private int[] reports = { 32767 };
    private int reportPosition;
    private int memoryChecks;
    private int deletionRequests;

    void report(int... values) {
      reports = values;
      reportPosition = 0;
      memoryChecks = 0;
      deletionRequests = 0;
    }

    @Override
    public short getAvailablePersistentMemory() {
      memoryChecks++;
      int position = Math.min(reportPosition++, reports.length - 1);
      return (short) reports[position];
    }

    @Override
    public void requestObjectDeletion() {
      deletionRequests++;
      super.requestObjectDeletion();
    }
  }
}
