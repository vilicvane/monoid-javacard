package monoidsecuritykey;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javax.smartcardio.CommandAPDU;
import monoid.Monoid;
import monoid.SafeDataShareable;
import monoid.SafeItemIteratorShareable;
import monoid.SafeItemShareable;
import monoidlib.CBORBufferWriter;
import monoidlib.CBORReader;
import monoidlib.CBORWriter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CredentialViewTest {

  private static final String APPLET = "f06d6f6e6f69647b01";
  private static final String OTHER_APPLET = "f06d6f6e6f69647b02";
  private CardSimulator simulator;
  private CredentialStore credentials;
  private Store store;

  @BeforeEach
  public void initialize() {
    simulator = new CardSimulator();
    simulator.installApplet(AIDUtil.create(APPLET), ViewApplet.class);
    simulator.installApplet(AIDUtil.create(OTHER_APPLET), ViewApplet.class);
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET)));
    credentials = new CredentialStore();
    store = new Store();
  }

  @Test
  public void constructedAndLoadedViewsOwnTheirPayloadsAndEmitTheSameFieldRanges() {
    for (byte[] name : new byte[][] {
      null,
      new byte[0],
      "\u7528\u6237".getBytes(StandardCharsets.UTF_8),
    }) {
      byte[] id = filled(32, 1);
      byte[] rp = filled(32, 2);
      byte[] user = filled(24, 3);
      byte[] point = filled(260, 4);
      Credential original = new Credential(
        id,
        rp,
        new byte[] { 'r', 'p' },
        user,
        name,
        new byte[0],
        true,
        point
      );
      Record record = new Record(original);
      byte[] window = new byte[64];
      Credential loaded = Credential.read(record.handle(), window);
      Arrays.fill(id, (byte) 9);
      Arrays.fill(rp, (byte) 9);
      Arrays.fill(user, (byte) 9);
      Arrays.fill(point, (byte) 9);
      Arrays.fill(window, (byte) 9);
      if (name != null) {
        Arrays.fill(name, (byte) 9);
      }

      Assertions.assertTrue(loaded.matchesId(filled(32, 1), (short) 0));
      Assertions.assertTrue(loaded.matchesRP(filled(32, 2)));
      Assertions.assertTrue(loaded.matchesPublicKey(filled(65, 4)));
      Assertions.assertArrayEquals(original.context(), loaded.context());
      byte[] contextOutput = filled(133, 9);
      short contextLength = loaded.writeContext(contextOutput, (short) 3);
      Assertions.assertEquals(78, contextLength);
      Assertions.assertArrayEquals(
        original.context(),
        Arrays.copyOfRange(contextOutput, 3, 3 + contextLength)
      );
      Assertions.assertArrayEquals(filled(3, 9), Arrays.copyOfRange(contextOutput, 0, 3));
      Assertions.assertArrayEquals(
        filled(contextOutput.length - 3 - contextLength, 9),
        Arrays.copyOfRange(contextOutput, 3 + contextLength, contextOutput.length)
      );
      Assertions.assertArrayEquals(
        write(original::writeDescriptor),
        write(loaded::writeDescriptor)
      );
      Assertions.assertArrayEquals(write(original::writePublicKey), write(loaded::writePublicKey));
      for (boolean verified : new boolean[] { false, true }) {
        Assertions.assertArrayEquals(
          write(writer -> original.writeUser(writer, verified)),
          write(writer -> loaded.writeUser(writer, verified))
        );
      }
      CBORReader userReader = reader(write(writer -> loaded.writeUser(writer, false)));
      Assertions.assertEquals(1, userReader.map());
      Assertions.assertArrayEquals(Constants.KEY_ID, userReader.text());
      Assertions.assertArrayEquals(filled(24, 3), userReader.bytes());
      Assertions.assertTrue(userReader.atEnd());
    }
  }

  @Test
  public void loadedViewsKeepLengthTextDuplicateAndMetadataValidation() {
    Record valid = new Record(credential(1, null, true));
    Record shortId = new Record(
      new Credential(
        filled(31, 1),
        filled(32, 2),
        new byte[0],
        new byte[] { 3 },
        null,
        null,
        true,
        filled(65, 4)
      )
    );
    rejects(shortId, CTAP.INVALID_LENGTH);

    Record shortPoint = new Record(credential(1, null, true));
    shortPoint.bytes = Arrays.copyOf(shortPoint.bytes, shortPoint.bytes.length - 1);
    shortPoint.bytes[shortPoint.bytes.length - 65] = 64;
    rejects(shortPoint, CTAP.INVALID_LENGTH);

    Record badText = new Record(credential(1, new byte[] { (byte) 0xc0 }, true));
    rejects(badText, CTAP.INVALID_CBOR);

    Record duplicate = new Record(credential(1, null, true));
    duplicate.bytes = Arrays.copyOf(duplicate.bytes, duplicate.bytes.length + 2);
    duplicate.bytes[0]++;
    duplicate.bytes[duplicate.bytes.length - 2] = 8;
    duplicate.bytes[duplicate.bytes.length - 1] = (byte) 0xf5;
    rejects(duplicate, CTAP.INVALID_CBOR);

    Record missingVersion = new Record(credential(1, null, true));
    byte[] missing = new byte[missingVersion.bytes.length - 2];
    missing[0] = (byte) (missingVersion.bytes[0] - 1);
    System.arraycopy(missingVersion.bytes, 3, missing, 1, missing.length - 1);
    missingVersion.bytes = missing;
    rejects(missingVersion, CTAP.MISSING_PARAMETER);

    Record badIndex = new Record(credential(1, null, true));
    badIndex.index[2] ^= 1;
    rejects(badIndex, CTAP.OTHER);
    Record badKey = new Record(credential(1, null, true));
    badKey.key[0] ^= 1;
    rejects(badKey, CTAP.OTHER);
    Credential loaded = Credential.read(valid.handle(), new byte[64]);
    Assertions.assertTrue(loaded.resident());
  }

  @Test
  public void cachedShortRecordsKeepIndependentPersistentPayloadsAcrossLongReads()
    throws Exception {
    Record named = store.add(credential(1, new byte[] { 'n' }, true));
    Record plain = store.add(credential(2, null, false));
    Record large = store.add(credential(3, filled(300, 'n'), true));
    Credential[] views = new Credential[3];
    run(() -> {
      views[0] = find(named);
      views[1] = find(large);
      Assertions.assertNotSame(views[0], views[1]);
      views[2] = find(plain);
      Assertions.assertNotSame(views[0], views[2]);
      Assertions.assertTrue(views[0].resident());
      Assertions.assertFalse(views[2].resident());
      Assertions.assertSame(views[0], find(named));
      Assertions.assertEquals(1, named.reads);
      Assertions.assertSame(views[1], find(large));
    });
    byte[] shortBuffer = backing(views[0]);
    Assertions.assertEquals(256, shortBuffer.length);
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(shortBuffer));
    Assertions.assertEquals(
      JCSystem.NOT_A_TRANSIENT_OBJECT,
      JCSystem.isTransient(backing(views[1]))
    );
    Assertions.assertTrue(views[0].matchesId(named.id, (short) 0));
    Assertions.assertEquals(2, reader(write(writer -> views[0].writeUser(writer, true))).map());
  }

  @Test
  public void growingPersistentWorkspaceIsReusedForSmallerRecords() {
    Record first = store.add(credential(1, filled(104, 'n'), true));
    Record second = store.add(credential(2, filled(105, 'n'), true));
    Assertions.assertEquals(257, first.bytes.length);
    Assertions.assertEquals(258, second.bytes.length);
    run(() -> {
      Assertions.assertTrue(APDU.getCurrentAPDUBuffer().length >= second.bytes.length);
      Credential previous = find(first);
      Credential grown = find(second);
      Assertions.assertNotSame(previous, grown);
      Assertions.assertSame(grown, find(first));
    });
  }

  @Test
  public void cacheSurvivesDeselectAndResetButChecksTheCurrentSession() throws Exception {
    Record named = store.add(
      new Credential(
        filled(32, 1),
        filled(32, 2),
        new byte[] { 'r', 'p' },
        filled(12, 3),
        new byte[] { 'n', 'a', 'm', 'e' },
        new byte[0],
        true,
        filled(65, 4)
      )
    );
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(named.index));
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(named.key));
    byte[] expectedIndex = named.index.clone();
    Credential[] cached = new Credential[1];
    byte[][] encodedUser = new byte[1][];
    SafeDataShareable[] oldSnapshot = new SafeDataShareable[1];
    run(() -> {
      cached[0] = find(named);
      encodedUser[0] = write(writer -> cached[0].writeUser(writer, true));
      oldSnapshot[0] = named.snapshot();
      Assertions.assertSame(cached[0], find(named));
      Assertions.assertEquals(1, named.reads);
    });
    short[] cachedState = (short[]) field(cached[0], "state");
    byte[] snapshot = (byte[]) field(cached[0], "stateSnapshot");
    byte[] saved = snapshot.clone();
    Assertions.assertEquals(JCSystem.CLEAR_ON_DESELECT, JCSystem.isTransient(cachedState));
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(snapshot));
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(OTHER_APPLET)));
    Assertions.assertArrayEquals(new short[11], cachedState);
    Assertions.assertArrayEquals(saved, snapshot);
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET)));
    run(() -> {
      Assertions.assertSame(cached[0], find(named));
      Assertions.assertArrayEquals(
        encodedUser[0],
        write(writer -> cached[0].writeUser(writer, true))
      );
      Assertions.assertTrue(cached[0].resident());
      Assertions.assertEquals(named.bytes.length, cached[0].getLength());
      Assertions.assertEquals(1, named.reads);
    });
    simulator.reset();
    Assertions.assertArrayEquals(new short[11], cachedState);
    Assertions.assertArrayEquals(saved, snapshot);
    store.newSession();
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET)));
    Assertions.assertArrayEquals(expectedIndex, named.index);
    Assertions.assertArrayEquals(filled(32, 2), named.key);
    run(() -> {
      assertStatus((short) 0x6982, oldSnapshot[0]::getLength);
      Assertions.assertSame(cached[0], find(named));
      Assertions.assertArrayEquals(
        encodedUser[0],
        write(writer -> cached[0].writeUser(writer, true))
      );
      Assertions.assertTrue(cached[0].matchesPublicKey(filled(65, 4)));
      Assertions.assertEquals(named.bytes.length, cached[0].getLength());
      Assertions.assertEquals(1, named.reads);
      Assertions.assertEquals(1, store.dataCalls);
    });
  }

  @Test
  public void reusedCacheSlotRestoresOnlyTheReplacementFieldsAfterReset() {
    Record named = store.add(registration(1, new byte[] { 'n' }, new byte[] { 'd' }, null));
    for (int index = 2; index <= CredentialStore.DISCOVERY_CAPACITY; index++) {
      store.add(credential(index, null, true));
    }
    Credential[] slot = new Credential[1];
    run(() -> {
      slot[0] = find(named);
      for (int index = 1; index < CredentialStore.DISCOVERY_CAPACITY; index++) {
        find(store.records.get(index));
      }
    });
    Record replacement = store.add(credential(9, null, false));
    run(() -> Assertions.assertSame(slot[0], find(replacement)));
    simulator.reset();
    store.newSession();
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET)));
    run(() -> {
      Credential restored = find(replacement);
      Assertions.assertSame(slot[0], restored);
      Assertions.assertFalse(restored.resident());
      Assertions.assertEquals(1, reader(write(writer -> restored.writeUser(writer, true))).map());
      Assertions.assertTrue(restored.matchesPublicKey(filled(65, 4)));
      Assertions.assertEquals(replacement.bytes.length, restored.getLength());
      Assertions.assertEquals(1, replacement.reads);
    });
  }

  @Test
  public void failedRefillCannotPublishStateBeforeSchemaAndMetadataValidation() throws Exception {
    Record first = store.add(credential(1, new byte[] { 'n' }, true));
    for (int index = 2; index <= CredentialStore.DISCOVERY_CAPACITY; index++) {
      store.add(credential(index, null, true));
    }
    Credential[] slot = new Credential[1];
    run(() -> {
      slot[0] = find(first);
      for (int index = 1; index < CredentialStore.DISCOVERY_CAPACITY; index++) {
        find(store.records.get(index));
      }
    });
    byte[] snapshot = (byte[]) field(slot[0], "stateSnapshot");
    byte[] saved = snapshot.clone();
    Record failing = store.add(credential(9, null, false));
    byte[] valid = failing.bytes;
    failing.bytes = Arrays.copyOf(valid, valid.length + 2);
    failing.bytes[0]++;
    failing.bytes[valid.length] = 8;
    failing.bytes[valid.length + 1] = (byte) 0xf5;
    assertStatus(CTAP.INVALID_CBOR, () -> run(() -> find(failing)));
    Assertions.assertArrayEquals(saved, snapshot);
    failing.bytes = new Record(credential(8, null, false)).bytes;
    assertStatus(CTAP.OTHER, () -> run(() -> find(failing)));
    Assertions.assertArrayEquals(saved, snapshot);
    simulator.reset();
    store.newSession();
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET)));
    run(() -> {
      // The rejected replacement overwrote the private record, so the old source must be reread.
      Assertions.assertTrue(find(first).matchesId(first.id, (short) 0));
      Assertions.assertEquals(2, first.reads);
    });
    failing.bytes = valid;
    run(() -> {
      Assertions.assertFalse(find(failing).resident());
      Assertions.assertEquals(3, failing.reads);
    });
  }

  @Test
  public void cacheReloadsSameLengthReplacementsAndSameIndexRecreation() {
    Record record = store.add(credential(1, new byte[] { 'a' }, true));
    run(() -> find(record));
    Record replacement = new Record(credential(1, new byte[] { 'b' }, false));
    Assertions.assertEquals(record.bytes.length, replacement.bytes.length);
    record.bytes = replacement.bytes;
    run(() -> {
      Credential current = find(record);
      Assertions.assertFalse(current.resident());
      Assertions.assertArrayEquals(
        write(writer -> credential(1, new byte[] { 'b' }, false).writeUser(writer, true)),
        write(writer -> current.writeUser(writer, true))
      );
      Assertions.assertEquals(2, record.reads);
    });
    store.records.remove(record);
    run(() -> {
      Assertions.assertNull(find(record));
    });
    Record recreated = store.add(credential(1, new byte[] { 'c' }, true));
    run(() -> {
      Credential current = find(recreated);
      Assertions.assertTrue(current.resident());
      Assertions.assertArrayEquals(
        write(writer -> credential(1, new byte[] { 'c' }, true).writeUser(writer, true)),
        write(writer -> current.writeUser(writer, true))
      );
      Assertions.assertEquals(1, recreated.reads);
    });
  }

  @Test
  public void warmCacheCannotBypassPermissionOrSecretChanges() {
    Record record = store.add(credential(1, null, true));
    run(() -> find(record));
    store.allowed = false;
    assertStatus((short) 0x6982, () -> run(() -> find(record)));
    store.allowed = true;
    record.secret = true;
    assertStatus((short) 0x6982, () -> run(() -> find(record)));
    Assertions.assertEquals(1, record.reads);
  }

  @Test
  public void cacheEvictsBeyondCapacityAndExplicitClearReloads() {
    Record[] records = new Record[CredentialStore.DISCOVERY_CAPACITY + 1];
    for (int index = 0; index < records.length; index++) {
      records[index] = store.add(credential(index + 1, null, true));
    }
    run(() -> {
      for (int index = 0; index < CredentialStore.DISCOVERY_CAPACITY; index++) {
        find(records[index]);
      }
      Assertions.assertEquals(CredentialStore.DISCOVERY_CAPACITY, store.dataCalls);
      for (int index = 0; index < CredentialStore.DISCOVERY_CAPACITY; index++) {
        find(records[index]);
        Assertions.assertEquals(1, records[index].reads);
      }
      Assertions.assertEquals(CredentialStore.DISCOVERY_CAPACITY, store.dataCalls);
      find(records[CredentialStore.DISCOVERY_CAPACITY]);
      find(records[0]);
      Assertions.assertEquals(2, records[0].reads);
      credentials.clear();
      find(records[0]);
      Assertions.assertEquals(3, records[0].reads);
    });
  }

  @Test
  public void failedRefillDoesNotPublishPartialOrMalformedCachedRecords() {
    Record first = store.add(credential(1, null, true));
    for (int index = 2; index <= CredentialStore.DISCOVERY_CAPACITY; index++) {
      store.add(credential(index, null, true));
    }
    run(() -> store.records.forEach(this::find));
    Record failing = store.add(credential(9, null, true));
    failing.onRead = () -> ISOException.throwIt(CTAP.OTHER);
    assertStatus(CTAP.OTHER, () -> run(() -> find(failing)));
    failing.onRead = null;
    run(() -> {
      Assertions.assertTrue(find(first).matchesId(first.id, (short) 0));
      Assertions.assertEquals(2, first.reads);
      Assertions.assertTrue(find(failing).matchesId(failing.id, (short) 0));
      Assertions.assertEquals(2, failing.reads);
    });
    byte[] valid = failing.bytes;
    failing.bytes = Arrays.copyOf(valid, valid.length + 2);
    failing.bytes[0]++;
    failing.bytes[valid.length] = 8;
    failing.bytes[valid.length + 1] = (byte) 0xf5;
    assertStatus(CTAP.INVALID_CBOR, () -> run(() -> find(failing)));
    failing.bytes = valid.clone();
    run(() -> {
      Assertions.assertTrue(find(failing).matchesId(failing.id, (short) 0));
      Assertions.assertEquals(4, failing.reads);
    });
  }

  @Test
  public void registrationWorkspaceKeepsPayloadButRefillsStateAfterDeselectAndReset()
    throws Exception {
    Record previous = store.add(credential(1, new byte[] { 'o', 'l', 'd' }, true));
    Credential registration = registration(2, new byte[] { 'n', 'e', 'w' }, new byte[0], null);
    byte[] encoded = new Record(registration).bytes;
    byte[] shortBuffer = backing(registration);
    Assertions.assertEquals(256, shortBuffer.length);
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(shortBuffer));
    run(() -> {
      Credential loaded = find(previous);
      Assertions.assertNotSame(registration, loaded);
      Assertions.assertTrue(loaded.matchesId(previous.id, (short) 0));
      Assertions.assertArrayEquals(encoded, new Record(registration).bytes);
    });

    Credential large = registration(3, filled(300, 'l'), null, registration);
    Assertions.assertNotSame(registration, large);
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(backing(large)));
    Assertions.assertArrayEquals(encoded, new Record(registration).bytes);

    Credential plain = registration(4, null, null, registration);
    Assertions.assertSame(registration, plain);
    Assertions.assertTrue(plain.matchesId(filled(32, 4), (short) 0));
    Assertions.assertEquals(1, reader(write(writer -> plain.writeUser(writer, true))).map());

    byte[] saved = shortBuffer.clone();
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(OTHER_APPLET)));
    Assertions.assertArrayEquals(saved, shortBuffer);
    Assertions.assertEquals(0, registration.getLength());
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET)));
    Credential renewed = registration(5, null, new byte[0], registration);
    Assertions.assertSame(registration, renewed);
    Assertions.assertTrue(renewed.matchesId(filled(32, 5), (short) 0));
    CBORReader user = reader(write(writer -> renewed.writeUser(writer, true)));
    Assertions.assertEquals(2, user.map());
    Assertions.assertArrayEquals(Constants.KEY_ID, user.text());
    Assertions.assertArrayEquals(new byte[] { 3 }, user.bytes());
    Assertions.assertArrayEquals(Constants.KEY_DISPLAY_NAME, user.text());
    Assertions.assertArrayEquals(new byte[0], user.text());
    Assertions.assertTrue(user.atEnd());

    saved = shortBuffer.clone();
    simulator.reset();
    Assertions.assertArrayEquals(saved, shortBuffer);
    Assertions.assertEquals(0, registration.getLength());
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET)));
    Credential reset = registration(6, new byte[] { 'n' }, null, registration);
    Assertions.assertSame(registration, reset);
    Assertions.assertTrue(reset.matchesId(filled(32, 6), (short) 0));
    user = reader(write(writer -> reset.writeUser(writer, true)));
    Assertions.assertEquals(2, user.map());
    Assertions.assertArrayEquals(Constants.KEY_ID, user.text());
    Assertions.assertArrayEquals(new byte[] { 3 }, user.bytes());
    Assertions.assertArrayEquals(Constants.KEY_NAME, user.text());
    Assertions.assertArrayEquals(new byte[] { 'n' }, user.text());
    Assertions.assertTrue(user.atEnd());
  }

  @Test
  public void discoveryRetainsIdsAndLaterReadsObserveChangesDeletionAndAccessFailure() {
    Record first = store.add(credential(1, null, true));
    Record second = store.add(credential(2, null, true));
    Record third = store.add(credential(3, null, true));
    CredentialStore.Selection[] selections = new CredentialStore.Selection[1];
    run(() -> {
      selections[0] = credentials.discover(store.service, filled(32, 2));
      Assertions.assertEquals(3, selections[0].count());
      Assertions.assertTrue(selections[0].takeFirst().matchesId(third.id, (short) 0));
      Assertions.assertNull(selections[0].takeFirst());
      Assertions.assertEquals(3, first.reads + second.reads + third.reads);
    });
    CredentialStore.Selection selection = selections[0];
    Record rewritten = new Record(credential(2, new byte[] { 'n', 'e', 'w' }, false));
    second.bytes = rewritten.bytes;
    run(() -> {
      Credential next = credentials.find(
        store.service,
        selection.ids,
        selection.offset((short) 1),
        filled(32, 2)
      );
      Assertions.assertFalse(next.resident());
      Assertions.assertEquals(2, reader(write(writer -> next.writeUser(writer, true))).map());
      Assertions.assertEquals(2, second.reads);
    });
    store.records.remove(first);
    run(() ->
      Assertions.assertNull(
        credentials.find(store.service, selection.ids, selection.offset((short) 2), filled(32, 2))
      )
    );
    store.allowed = false;
    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      run(() -> find(third))
    );
    Assertions.assertEquals((short) 0x6982, exception.getReason());
  }

  @Test
  public void discoveryReusesCachedLastMatchWhenTrailingRecordIsNonresident() {
    Record first = store.add(credential(1, null, true));
    Record last = store.add(credential(2, null, true));
    Record nonresident = store.add(credential(3, null, false));
    run(() -> {
      CredentialStore.Selection selection = credentials.discover(store.service, filled(32, 2));
      Assertions.assertEquals(2, selection.count());
      Assertions.assertTrue(selection.takeFirst().matchesId(last.id, (short) 0));
      Assertions.assertEquals(1, first.reads);
      Assertions.assertEquals(1, last.reads);
      Assertions.assertEquals(1, nonresident.reads);
    });
  }

  @Test
  public void shortReadsStillBindTheFullIdAndStoredMetadata() {
    Record record = store.add(credential(1, null, true));
    byte[] collision = filled(32, 1);
    collision[31] = 2;
    run(() -> {
      Assertions.assertNotNull(find(record));
      Assertions.assertNull(credentials.find(store.service, collision, record.key));
      Assertions.assertEquals(1, record.reads);
    });
    Record changedId = new Record(
      new Credential(
        collision,
        filled(32, 2),
        new byte[0],
        new byte[] { 3 },
        null,
        null,
        true,
        filled(65, 4)
      )
    );
    record.bytes = changedId.bytes;
    run(() -> Assertions.assertNull(find(record)));

    record.bytes = new Record(credential(2, null, true)).bytes;
    ISOException wrongPrefix = Assertions.assertThrows(ISOException.class, () ->
      run(() -> find(record))
    );
    Assertions.assertEquals(CTAP.OTHER, wrongPrefix.getReason());

    record.bytes = new Record(
      new Credential(
        filled(32, 1),
        filled(32, 3),
        new byte[0],
        new byte[] { 3 },
        null,
        null,
        true,
        filled(65, 4)
      )
    ).bytes;
    ISOException wrongHash = Assertions.assertThrows(ISOException.class, () ->
      run(() -> find(record))
    );
    Assertions.assertEquals(CTAP.OTHER, wrongHash.getReason());
    // The new generic read filters metadata before decoding a record belonging to another key.
    run(() -> Assertions.assertNull(credentials.find(store.service, record.id, filled(32, 4))));
  }

  @Test
  public void boundedDiscoveryRetainsIdsButInvalidatesSelectionOnDeselectAndReset() {
    for (int index = 1; index <= CredentialStore.DISCOVERY_CAPACITY; index++) {
      store.add(credential(index, null, true));
    }
    CredentialStore.Selection[] selected = new CredentialStore.Selection[1];
    run(() -> {
      selected[0] = credentials.discover(store.service, filled(32, 2));
      Assertions.assertEquals(CredentialStore.DISCOVERY_CAPACITY, selected[0].count());
      Assertions.assertEquals(0, store.iteratorCalls);
      CredentialStore.Selection again = credentials.discover(store.service, filled(32, 2));
      Assertions.assertSame(selected[0], again);
      Assertions.assertEquals(2, store.indexCalls);
      Assertions.assertEquals(0, store.iteratorCalls);
      for (Record record : store.records) {
        Assertions.assertEquals(1, record.reads);
      }
    });
    byte[] ids = selected[0].ids.clone();
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(selected[0].ids));
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(OTHER_APPLET)));
    Assertions.assertEquals(0, selected[0].count());
    Assertions.assertNull(selected[0].takeFirst());
    Assertions.assertArrayEquals(ids, selected[0].ids);
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET)));
    store.records.clear();
    Record renewed = store.add(credential(9, null, true));
    run(() -> {
      CredentialStore.Selection again = credentials.discover(store.service, filled(32, 2));
      Assertions.assertSame(selected[0], again);
      Assertions.assertEquals(1, again.count());
      Assertions.assertTrue(again.takeFirst().matchesId(renewed.id, (short) 0));
    });

    ids = selected[0].ids.clone();
    simulator.reset();
    Assertions.assertEquals(0, selected[0].count());
    Assertions.assertNull(selected[0].takeFirst());
    Assertions.assertArrayEquals(ids, selected[0].ids);
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET)));
    store.records.clear();
    run(() -> {
      CredentialStore.Selection empty = credentials.discover(store.service, filled(32, 2));
      Assertions.assertSame(selected[0], empty);
      Assertions.assertEquals(0, empty.count());
      Assertions.assertNull(empty.takeFirst());
    });
  }

  @Test
  public void discoveryFallsBackBeyondCapacityAndForLongRecordsWithoutTruncation() {
    for (int index = 1; index <= CredentialStore.DISCOVERY_CAPACITY + 1; index++) {
      store.add(credential(index, null, true));
    }
    run(() -> {
      CredentialStore.Selection all = credentials.discover(store.service, filled(32, 2));
      Assertions.assertEquals(CredentialStore.DISCOVERY_CAPACITY + 1, all.count());
      Assertions.assertEquals(1, store.iteratorCalls);
      for (short position = 0; position < all.count(); position++) {
        int id = all.count() - position;
        Assertions.assertArrayEquals(
          filled(32, id),
          Arrays.copyOfRange(all.ids, all.offset(position), all.offset(position) + 32)
        );
      }
    });
    store.records.clear();
    Record large = store.add(credential(7, filled(512, 'x'), true));
    run(() -> {
      CredentialStore.Selection bounded = credentials.discover(store.service, filled(32, 2));
      Assertions.assertEquals(1, bounded.count());
      Assertions.assertTrue(bounded.takeFirst().matchesId(large.id, (short) 0));
      Assertions.assertEquals(1, store.iteratorCalls);
    });
  }

  private Credential find(Record record) {
    return credentials.find(store.service, record.id, record.key);
  }

  private static Credential credential(int id, byte[] name, boolean resident) {
    return new Credential(
      filled(32, id),
      filled(32, 2),
      new byte[] { 'r', 'p' },
      new byte[] { 3 },
      name,
      null,
      resident,
      filled(65, 4)
    );
  }

  private static Credential registration(
    int id,
    byte[] name,
    byte[] displayName,
    Credential reusable
  ) {
    return Credential.create(
      filled(32, id),
      filled(32, 2),
      new byte[] { 'r', 'p' },
      new byte[] { 3 },
      name,
      displayName,
      true,
      filled(65, 4),
      reusable
    );
  }

  private static void rejects(Record record, short reason) {
    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      Credential.read(record.handle(), new byte[64])
    );
    Assertions.assertEquals(reason, exception.getReason());
  }

  private static void assertStatus(short reason, Runnable operation) {
    ISOException exception = Assertions.assertThrows(ISOException.class, operation::run);
    Assertions.assertEquals(reason, exception.getReason());
  }

  private static byte[] backing(Credential credential) throws Exception {
    return (byte[]) field(credential, "data");
  }

  private static Object field(Credential credential, String name) throws Exception {
    java.lang.reflect.Field field = Credential.class.getDeclaredField(name);
    field.setAccessible(true);
    return field.get(credential);
  }

  private static byte[] write(Consumer<CBORWriter> encode) {
    byte[] data = new byte[1200];
    CBORBufferWriter writer = new CBORBufferWriter(data, (short) 0, CTAP.LIMIT_EXCEEDED);
    encode.accept(writer);
    return Arrays.copyOf(data, writer.getLength());
  }

  private static CBORReader reader(byte[] data) {
    return new CBORReader(data, (short) 0, (short) data.length);
  }

  private static byte[] filled(int length, int value) {
    byte[] bytes = new byte[length];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }

  private void run(Runnable operation) {
    ViewApplet.operation = operation;
    ViewApplet.failure = null;
    try {
      Assertions.assertEquals(
        0x9000,
        simulator.transmitCommand(new CommandAPDU(0, 1, 0, 0)).getSW()
      );
      if (ViewApplet.failure instanceof RuntimeException) {
        throw (RuntimeException) ViewApplet.failure;
      }
      if (ViewApplet.failure != null) {
        throw (Error) ViewApplet.failure;
      }
    } finally {
      ViewApplet.operation = null;
      ViewApplet.failure = null;
    }
  }

  public static final class ViewApplet extends Applet {

    private static Runnable operation;
    private static Throwable failure;

    public static void install(byte[] buffer, short offset, byte length) {
      new ViewApplet().register();
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

  /** Immutable metadata and replaceable bytes model the existing Safe handle contract. */
  private static final class Record implements SafeDataShareable {

    byte[] bytes;
    final byte[] id = new byte[32];
    final byte[] index;
    final byte[] key;
    Store owner;
    boolean secret;
    Runnable onRead;
    int reads;

    Record(Credential credential) {
      bytes = new byte[credential.getLength()];
      credential.read((short) 0, bytes, (short) 0, (short) bytes.length);
      credential.copyId(id, (short) 0);
      // Safe owns persistent metadata; the exported credential helpers return reset-cleared globals.
      index = credential.index().clone();
      key = credential.key().clone();
    }

    @Override
    public short getLength() {
      return (short) bytes.length;
    }

    @Override
    public void read(short offset, byte[] buffer, short bufferOffset, short length) {
      reads++;
      System.arraycopy(bytes, offset, buffer, bufferOffset, length);
      if (onRead != null) {
        onRead.run();
      }
    }

    short readPrefix(byte[] dest, short offset, short capacity) {
      read((short) 0, dest, offset, (short) Math.min(capacity, bytes.length));
      return (short) bytes.length;
    }

    SafeItemShareable handle() {
      return service(SafeItemShareable.class, (proxy, method, arguments) -> {
        switch (method.getName()) {
          case "getIndex":
            return index;
          case "getKey":
            return key;
          case "getData":
            return snapshot();
          default:
            throw new UnsupportedOperationException(method.getName());
        }
      });
    }

    SafeDataShareable snapshot() {
      if (owner != null) {
        owner.assertReadable(this);
      }
      return new Snapshot(this);
    }
  }

  /** Old readers stay invalid after reset, while a new authorized session may validate their bytes. */
  private static final class Snapshot implements SafeDataShareable {

    final Record record;
    final byte[] bytes;
    final int session;

    Snapshot(Record record) {
      this.record = record;
      bytes = record.bytes;
      session = record.owner == null ? 0 : record.owner.session;
    }

    @Override
    public short getLength() {
      assertReadable();
      return (short) bytes.length;
    }

    @Override
    public void read(short offset, byte[] buffer, short bufferOffset, short length) {
      assertReadable();
      record.read(offset, buffer, bufferOffset, length);
    }

    private void assertReadable() {
      if (record.owner != null) {
        record.owner.assertReadable(record);
        if (session != record.owner.session) {
          ISOException.throwIt((short) 0x6982);
        }
      }
      if (record.bytes != bytes) {
        ISOException.throwIt((short) 0x6985);
      }
    }
  }

  private static final class Store {

    final List<Record> records = new ArrayList<>();
    boolean allowed = true;
    int iteratorCalls;
    int indexCalls;
    int dataCalls;
    int session;
    Monoid service = newService();

    private Monoid newService() {
      return service(Monoid.class, (proxy, method, arguments) -> {
        if (!allowed) {
          ISOException.throwIt((short) 0x6982);
        }
        if (method.getName().equals("isDataCurrent")) {
          if (!(arguments[0] instanceof Snapshot)) {
            return false;
          }
          Snapshot snapshot = (Snapshot) arguments[0];
          Record record = snapshot.record;
          if (record.owner != this || !records.contains(record)) {
            return false;
          }
          assertReadable(record);
          return record.bytes == snapshot.bytes;
        }
        if (method.getName().equals("get")) {
          return records
            .stream()
            .filter(record -> Arrays.equals(record.index, (byte[]) arguments[0]))
            .map(Record::handle)
            .findFirst()
            .orElse(null);
        }
        if (method.getName().equals("getData") || method.getName().equals("readData")) {
          boolean snapshot = method.getName().equals("getData");
          if (snapshot) {
            dataCalls++;
          }
          for (Record record : records) {
            if (
              Arrays.equals(
                record.index,
                Arrays.copyOfRange(
                  (byte[]) arguments[0],
                  (short) arguments[1],
                  (short) arguments[1] + 10
                )
              ) &&
              Arrays.equals(
                record.key,
                Arrays.copyOfRange(
                  (byte[]) arguments[2],
                  (short) arguments[3],
                  (short) arguments[3] + (short) arguments[4]
                )
              )
            ) {
              assertReadable(record);
              if (snapshot) {
                return record.snapshot();
              }
              return record.readPrefix(
                (byte[]) arguments[5],
                (short) arguments[6],
                (short) arguments[7]
              );
            }
          }
          return snapshot ? null : (short) -1;
        }
        if (method.getName().equals("listIndices")) {
          indexCalls++;
          byte[] key = Arrays.copyOfRange(
            (byte[]) arguments[1],
            (short) arguments[2],
            (short) arguments[2] + (short) arguments[3]
          );
          short count = 0;
          for (Record record : records) {
            if (
              record.key.length >= key.length &&
              Arrays.equals(key, Arrays.copyOf(record.key, key.length))
            ) {
              if (count < (short) arguments[6]) {
                System.arraycopy(
                  record.index,
                  0,
                  (byte[]) arguments[4],
                  (short) arguments[5] + count * 10,
                  10
                );
              }
              count++;
            }
          }
          return count;
        }
        if (method.getName().equals("list")) {
          iteratorCalls++;
          List<Record> selected = new ArrayList<>();
          for (Record record : records) {
            if (Arrays.equals(record.key, (byte[]) arguments[1])) {
              selected.add(record);
            }
          }
          int[] position = { 0 };
          return service(SafeItemIteratorShareable.class, (iterator, operation, parameters) -> {
            switch (operation.getName()) {
              case "getCount":
                return (short) selected.size();
              case "next":
                return position[0] == selected.size() ? null : selected.get(position[0]++).handle();
              case "nextData":
                if (position[0] == selected.size()) {
                  return (short) -1;
                }
                Record record = selected.get(position[0]++);
                Assertions.assertArrayEquals(record.key, (byte[]) parameters[0]);
                System.arraycopy(
                  record.index,
                  0,
                  (byte[]) parameters[1],
                  (short) parameters[2],
                  10
                );
                return record.readPrefix(
                  (byte[]) parameters[3],
                  (short) parameters[4],
                  (short) parameters[5]
                );
              default:
                throw new UnsupportedOperationException(operation.getName());
            }
          });
        }
        throw new UnsupportedOperationException(method.getName());
      });
    }

    void newSession() {
      session++;
      service = newService();
    }

    void assertReadable(Record record) {
      if (!allowed || record.secret) {
        ISOException.throwIt((short) 0x6982);
      }
      if (!records.contains(record)) {
        ISOException.throwIt((short) 0x6985);
      }
    }

    Record add(Credential credential) {
      Record record = new Record(credential);
      record.owner = this;
      records.add(record);
      return record;
    }
  }
}
