package monoidsecuritykey;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoid.Monoid;
import monoid.SafeItemIteratorShareable;
import monoid.SafeItemShareable;
import monoidlib.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CredentialStoreTest {

  private final CredentialStore credentials = new CredentialStore();
  private MemoryStore store;
  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    simulator = new CardSimulator();
    simulator.installApplet(AIDUtil.create("f06d6f6e6f69647d01"), StoreApplet.class);
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create("f06d6f6e6f69647d01")));
    store = new MemoryStore();
  }

  @Test
  public void emptyReplacementSearchDoesNotCreateAnIteratorOrHandles() {
    store.failOnNext = true;
    Credential next = credential(1, 1, 1);
    save(next);
    Assertions.assertEquals(Arrays.asList(next), store.items);
    Assertions.assertEquals(1, store.directCreates);
    Assertions.assertEquals(1, store.indexLists);
    Assertions.assertEquals(0, store.iterators);
    Assertions.assertEquals(0, store.directReads);
    Assertions.assertEquals(0, store.itemGets);
  }

  @Test
  public void boundedReplacementSearchReadsAllAccountsWithoutCreatingUnneededHandles() {
    for (int index = 1; index <= 4; index++) {
      store.add(credential(index, 1, index));
    }
    Credential next = credential(5, 1, 5);
    save(next);

    Assertions.assertEquals(5, store.items.size());
    Assertions.assertSame(next, store.items.get(4));
    Assertions.assertEquals(1, store.indexLists);
    Assertions.assertEquals(0, store.iterators);
    Assertions.assertEquals(4, store.directReads);
    Assertions.assertEquals(0, store.itemGets);
  }

  @Test
  public void boundedReplacementSearchOnlyGetsMatchingAccountHandles() {
    Credential previous = credential(1, 1, 1);
    Credential otherAccount = credential(2, 1, 2);
    Credential next = credential(4, 1, 1);
    store.add(previous);
    store.add(otherAccount);
    store.add(next);
    save(next);

    Assertions.assertEquals(Arrays.asList(otherAccount, next), store.items);
    Assertions.assertEquals(0, store.iterators);
    Assertions.assertEquals(3, store.directReads);
    Assertions.assertEquals(1, store.itemGets);
  }

  @Test
  public void largerReplacementSearchRetainsIteratorAndInterruptedRetrySemantics() {
    Credential previous = credential(1, 1, 1);
    store.add(previous);
    for (int index = 2; index <= 5; index++) {
      store.add(credential(index, 1, index));
    }
    Credential interrupted = credential(6, 1, 1);
    store.failAfterCreate = true;
    Assertions.assertThrows(ISOException.class, () -> save(interrupted));
    Assertions.assertTrue(store.items.contains(previous));
    Assertions.assertTrue(store.items.contains(interrupted));

    Credential retry = credential(7, 1, 1);
    save(retry);
    Assertions.assertEquals(5, store.items.size());
    Assertions.assertFalse(store.items.contains(previous));
    Assertions.assertFalse(store.items.contains(interrupted));
    Assertions.assertSame(retry, store.items.get(4));
    Assertions.assertEquals(2, store.indexLists);
    Assertions.assertEquals(2, store.iterators);
    Assertions.assertEquals(0, store.directReads);
    Assertions.assertEquals(0, store.itemGets);
  }

  @Test
  public void directCreateOwnsItsRecordAndMinimumWindowsKeepTheCallbackFallback() {
    store.copyCreated = true;
    Credential shortRecord = credential(1, 1, 1);
    save(shortRecord);
    Assertions.assertEquals(1, store.directCreates);
    Assertions.assertEquals(0, store.callbackCreates);
    Assertions.assertTrue(store.items.get(0).sameId(shortRecord));

    Credential next = credential(2, 1, 1);
    store.creating = next;
    Assertions.assertTrue(next.create(store.service, Utils.makeGlobalByteArray((short) 133)));
    Assertions.assertEquals(1, store.callbackCreates);
    Assertions.assertTrue(store.items.get(1).sameId(next));
  }

  @Test
  public void directCreateReservesTheIndexAtTheExactWindowBoundary() {
    for (int length : new int[] { 5, 6 }) {
      byte[] id = new byte[32];
      id[0] = (byte) length;
      Credential credential = new Credential(
        id,
        new byte[32],
        new byte[32],
        new byte[length],
        new byte[] { 1 },
        null,
        null,
        new byte[65]
      );
      Assertions.assertEquals(length + 181, credential.getLength());
      store.creating = credential;
      Assertions.assertTrue(
        credential.create(store.service, Utils.makeGlobalByteArray((short) 260))
      );
    }
    Assertions.assertEquals(1, store.directCreates);
    Assertions.assertEquals(1, store.callbackCreates);
  }

  @Test
  public void creationFailurePreservesThePreviousCredential() {
    Credential previous = credential(1, 1, 1);
    store.add(previous);
    store.failBeforeCreate = true;

    Assertions.assertThrows(ISOException.class, () -> save(credential(2, 1, 1)));
    Assertions.assertEquals(Arrays.asList(previous), store.items);
  }

  @Test
  public void reusedRegistrationKeepsCommittedCopiesAcrossInterruptedReplacement() {
    store.copyCreated = true;
    Credential previous = credential(1, 1, 1);
    store.add(previous);
    Credential staging = registration(2, null);
    store.failAfterCreate = true;

    Assertions.assertThrows(ISOException.class, () -> save(staging));
    Assertions.assertEquals(2, store.items.size());
    Assertions.assertSame(previous, store.items.get(0));
    Credential committed = store.items.get(1);
    Assertions.assertNotSame(staging, committed);
    Assertions.assertTrue(committed.sameId(credential(2, 1, 1)));

    Assertions.assertSame(staging, registration(3, staging));
    Assertions.assertTrue(previous.sameId(credential(1, 1, 1)));
    Assertions.assertTrue(committed.sameId(credential(2, 1, 1)));
    save(staging);
    Assertions.assertEquals(1, store.items.size());
    Assertions.assertNotSame(staging, store.items.get(0));
    Assertions.assertTrue(store.items.get(0).sameId(credential(3, 1, 1)));
  }

  @Test
  public void retryRemovesAllRecordsLeftByInterruptedReplacement() {
    Credential previous = credential(1, 1, 1);
    Credential otherAccount = credential(2, 1, 2);
    Credential otherRP = credential(3, 2, 1);
    store.add(previous);
    store.add(otherAccount);
    store.add(otherRP);
    Credential interrupted = credential(5, 1, 1);
    store.failAfterCreate = true;

    Assertions.assertThrows(ISOException.class, () -> save(interrupted));
    Assertions.assertTrue(store.items.contains(previous));
    Assertions.assertTrue(store.items.contains(interrupted));

    Credential retry = credential(6, 1, 1);
    save(retry);
    Assertions.assertEquals(Arrays.asList(otherAccount, otherRP, retry), store.items);
  }

  @Test
  public void retryFinishesAfterDuplicateCleanupWasInterrupted() {
    Credential first = credential(1, 1, 1);
    Credential second = credential(2, 1, 1);
    store.add(first);
    store.add(second);
    Credential interrupted = credential(3, 1, 1);
    store.failAfterRemoval = true;

    Assertions.assertThrows(ISOException.class, () -> save(interrupted));
    Assertions.assertEquals(Arrays.asList(first), store.items);

    Credential retry = credential(4, 1, 1);
    save(retry);
    Assertions.assertEquals(Arrays.asList(retry), store.items);
    save(retry);
    Assertions.assertEquals(Arrays.asList(retry), store.items);
  }

  @Test
  public void retryReclaimsDuplicatesBeforeRequiringSpaceForAnotherRecord() {
    Credential previous = credential(1, 1, 1);
    store.add(previous);
    store.capacity = 2;
    store.failAfterCreate = true;
    Assertions.assertThrows(ISOException.class, () -> save(credential(2, 1, 1)));
    Assertions.assertEquals(2, store.items.size());

    Credential retry = credential(3, 1, 1);
    save(retry);
    Assertions.assertEquals(Arrays.asList(retry), store.items);
  }

  @Test
  public void duplicateCleanupCanCommitBeforeSpaceBecomesAvailable() {
    Credential previous = credential(1, 1, 1);
    store.add(previous);
    store.add(credential(2, 1, 1));
    store.failBeforeCreate = true;
    Assertions.assertThrows(ISOException.class, () -> save(credential(3, 1, 1)));
    Assertions.assertEquals(Arrays.asList(previous), store.items);

    Credential retry = credential(4, 1, 1);
    save(retry);
    Assertions.assertEquals(Arrays.asList(retry), store.items);
  }

  @Test
  public void residentReplacementPreservesOtherScopesInBothSearchPaths() {
    byte[] activeScope = new byte[32];
    activeScope[0] = 1;

    for (int count : new int[] { 3, 5 }) {
      store = new MemoryStore();
      Credential inactive = credential(1, 1, 1);
      store.add(inactive);

      for (int id = 2; id < count + 2; id++) {
        store.add(credential(id, 1, 1, activeScope));
      }

      Credential replacement = credential(10, 1, 1, activeScope);
      credentials.setScope(activeScope, (short) 0);
      save(replacement);

      Assertions.assertEquals(Arrays.asList(inactive, replacement), store.items);
      Assertions.assertEquals(count > CredentialStore.DISCOVERY_CAPACITY ? 1 : 0, store.iterators);

      credentials.setScope(new byte[32], (short) 0);
      Credential returned = credential(11, 1, 1);
      save(returned);
      Assertions.assertEquals(Arrays.asList(replacement, returned), store.items);
    }
  }

  private static Credential credential(int id, int rp, int user) {
    return credential(id, rp, user, new byte[32]);
  }

  private static Credential credential(int id, int rp, int user, byte[] scope) {
    byte[] credentialId = new byte[32];
    credentialId[0] = (byte) id;
    byte[] rpHash = new byte[32];
    rpHash[0] = (byte) rp;
    return new Credential(
      credentialId,
      rpHash,
      scope,
      new byte[] { (byte) rp },
      new byte[] { (byte) user },
      null,
      null,
      new byte[65]
    );
  }

  private static Credential registration(int id, Credential reusable) {
    byte[] credentialId = new byte[32];
    credentialId[0] = (byte) id;
    byte[] rpHash = new byte[32];
    rpHash[0] = 1;
    return Credential.create(
      credentialId,
      rpHash,
      new byte[32],
      new byte[] { 1 },
      new byte[] { 1 },
      null,
      null,
      new byte[65],
      reusable
    );
  }

  private void save(Credential credential) {
    store.creating = credential;
    StoreApplet.operation = () -> credentials.save(store.service, credential);
    StoreApplet.failure = null;
    try {
      ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(0, 1, 0, 0));
      Assertions.assertEquals(0x9000, response.getSW());
      if (StoreApplet.failure instanceof RuntimeException) {
        throw (RuntimeException) StoreApplet.failure;
      }
      if (StoreApplet.failure != null) {
        throw (Error) StoreApplet.failure;
      }
    } finally {
      StoreApplet.operation = null;
      StoreApplet.failure = null;
    }
  }

  /** Supplies a real APDU lifetime while the model still injects committed-step failures. */
  public static final class StoreApplet extends Applet {

    private static Runnable operation;
    private static Throwable failure;

    public static void install(byte[] buffer, short offset, byte length) {
      new StoreApplet().register();
    }

    @Override
    public void process(APDU apdu) {
      if (!selectingApplet()) {
        try {
          operation.run();
        } catch (RuntimeException | Error exception) {
          failure = exception;
        }
      }
    }
  }

  @SuppressWarnings("unchecked")
  private static <T> T service(Class<T> type, InvocationHandler handler) {
    return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, handler);
  }

  /** Models committed steps and injected failures, not the Java Card firewall or rollback. */
  private static final class MemoryStore {

    final List<Credential> items = new ArrayList<>();
    boolean failBeforeCreate;
    boolean failAfterCreate;
    boolean failAfterRemoval;
    boolean copyCreated;
    boolean failOnNext;
    Credential creating;
    int directCreates;
    int callbackCreates;
    int indexLists;
    int iterators;
    int directReads;
    int itemGets;
    int capacity = Integer.MAX_VALUE;
    int revision;

    final Monoid service = service(Monoid.class, (proxy, method, arguments) -> {
      if (method.getName().equals("listIndices")) {
        indexLists++;
        byte[] metadata = Arrays.copyOfRange(
          (byte[]) arguments[1],
          (Short) arguments[2],
          (Short) arguments[2] + (Short) arguments[3]
        );
        List<Credential> selected = selected(metadata);
        if (selected.size() <= (Short) arguments[6]) {
          byte[] output = (byte[]) arguments[4];
          short offset = (Short) arguments[5];
          for (Credential item : selected) {
            System.arraycopy(item.index(), 0, output, offset, 10);
            offset += 10;
          }
        }
        return (short) selected.size();
      }
      if (method.getName().equals("readData")) {
        directReads++;
        byte[] index = Arrays.copyOfRange(
          (byte[]) arguments[0],
          (Short) arguments[1],
          (Short) arguments[1] + 10
        );
        byte[] metadata = Arrays.copyOfRange(
          (byte[]) arguments[2],
          (Short) arguments[3],
          (Short) arguments[3] + (Short) arguments[4]
        );
        Credential item = find(index);
        if (item == null || !Arrays.equals(item.metadata(), metadata)) {
          return (short) -1;
        }
        short length = item.getLength();
        item.read(
          (short) 0,
          (byte[]) arguments[5],
          (Short) arguments[6],
          (short) Math.min(length, (Short) arguments[7])
        );
        return length;
      }
      if (method.getName().equals("get")) {
        itemGets++;
        Credential item = find((byte[]) arguments[0]);
        return item == null ? null : handle(item);
      }
      if (method.getName().equals("list")) {
        iterators++;
        List<Credential> selected = selected((byte[]) arguments[1]);
        int expectedRevision = revision;
        int[] position = { 0 };
        return service(SafeItemIteratorShareable.class, (iterator, operation, parameters) -> {
          Assertions.assertEquals(expectedRevision, revision, "Finish scanning before mutation");
          if (operation.getName().equals("getCount")) {
            return (short) selected.size();
          }
          if (operation.getName().equals("next")) {
            Assertions.assertFalse(failOnNext, "An empty iterator need not be advanced");
            return position[0] == selected.size() ? null : handle(selected.get(position[0]++));
          }
          throw new UnsupportedOperationException(operation.getName());
        });
      }
      if (method.getName().equals("create") || method.getName().equals("createData")) {
        Assertions.assertEquals(0, JCSystem.getTransactionDepth());
        boolean direct = method.getName().equals("createData");
        Credential item;
        if (direct) {
          directCreates++;
          byte[] input = (byte[]) arguments[6];
          short offset = (Short) arguments[7];
          short length = (Short) arguments[8];
          byte[] expected = new byte[creating.getLength()];
          creating.read((short) 0, expected, (short) 0, (short) expected.length);
          Assertions.assertArrayEquals(
            expected,
            Arrays.copyOfRange(input, offset, offset + length)
          );
          Assertions.assertArrayEquals(
            creating.index(),
            Arrays.copyOfRange(
              (byte[]) arguments[0],
              (Short) arguments[1],
              (Short) arguments[1] + 10
            )
          );
          Assertions.assertArrayEquals(
            creating.metadata(),
            Arrays.copyOfRange(
              (byte[]) arguments[2],
              (Short) arguments[3],
              (Short) arguments[3] + (Short) arguments[4]
            )
          );
          Assertions.assertNull(arguments[5]);
          Assertions.assertEquals(false, arguments[9]);
          item = creating;
        } else {
          callbackCreates++;
          item = (Credential) arguments[3];
        }
        if (failBeforeCreate) {
          failBeforeCreate = false;
          ISOException.throwIt(CTAP.OTHER);
        }
        for (Credential existing : items) {
          if (existing.sameId(item)) {
            return direct ? false : null;
          }
        }
        if (items.size() >= capacity) {
          ISOException.throwIt(CTAP.KEY_STORE_FULL);
        }
        Credential saved = copyCreated ? Credential.read(handle(item), new byte[64]) : item;
        if (direct) {
          Arrays.fill((byte[]) arguments[6], (byte) 0x5a);
        }
        add(saved);
        if (failAfterCreate) {
          failAfterCreate = false;
          ISOException.throwIt(CTAP.OTHER);
        }
        return direct ? true : handle(saved);
      }
      throw new UnsupportedOperationException(method.getName());
    });

    void add(Credential credential) {
      items.add(credential);
      revision++;
    }

    private List<Credential> selected(byte[] metadata) {
      List<Credential> selected = new ArrayList<>();
      for (Credential item : items) {
        if (item.matchesMetadata(metadata)) {
          selected.add(item);
        }
      }
      return selected;
    }

    private Credential find(byte[] index) {
      for (Credential item : items) {
        if (Arrays.equals(item.index(), index)) {
          return item;
        }
      }
      return null;
    }

    private SafeItemShareable handle(Credential credential) {
      return service(SafeItemShareable.class, (proxy, method, arguments) -> {
        switch (method.getName()) {
          case "getIndex":
            return credential.index();
          case "getMetadata":
            return credential.metadata();
          case "getData":
            return credential;
          case "remove":
            Assertions.assertEquals(0, JCSystem.getTransactionDepth());
            items.remove(credential);
            revision++;
            if (failAfterRemoval) {
              failAfterRemoval = false;
              ISOException.throwIt(CTAP.OTHER);
            }
            return null;
          default:
            throw new UnsupportedOperationException(method.getName());
        }
      });
    }
  }
}
