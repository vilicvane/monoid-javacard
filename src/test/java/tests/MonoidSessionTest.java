package tests;

import static tests.MonoidItemTransferTest.fields;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.bouncycastle.crypto.params.ECDomainParameters;
import com.licel.jcardsim.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.licel.jcardsim.bouncycastle.crypto.signers.ECDSASigner;
import com.licel.jcardsim.utils.AIDUtil;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import javacard.framework.AID;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import monoid.Monoid;
import monoid.SafeDataShareable;
import monoid.SafeItemIteratorShareable;
import monoid.SafeItemShareable;
import monoidlib.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;

public class MonoidSessionTest {

  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );
  private static final AID CLIENT_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_NAMESPACE}}7c01"
    "f06d6f6e6f69647c01"
  );
  private static final AID OTHER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_NAMESPACE}}7c02"
    "f06d6f6e6f69647c02"
  );

  @Test
  public void tokenAuthenticationWorksWithoutAPDUAuthenticationAndRejectsThePublicHash()
    throws Exception {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      fixture.card.reset();
      Monoid session = fixture.connect(false);
      assertStatus(0x6982, () -> session.list((short) 0));
      byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(fixture.client.token);
      assertStatus(0x6982, () -> session.authenticate(global(hash)));
      session.authenticate(global(fixture.client.token));
      Assertions.assertEquals(0, session.list((short) 0).getCount());
      assertStatus(0x6982, () -> session.authenticate(global(new byte[32])));
      assertStatus(0x6982, () -> session.list((short) 0));
      session.authenticate(global(fixture.client.token));
      Assertions.assertEquals(0, session.list((short) 0).getCount());
    }
  }

  @Test
  public void rangedAuthenticationRehashesEveryTokenAndReusesSafePersistentWorkspace()
    throws Exception {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connectReusable(false);
      Object resources = privateField(privateField(session, "safe"), "appletGrants");
      Assertions.assertNull(privateField(resources, "tokenHash"));
      Assertions.assertNull(privateField(resources, "tokenDigest"));
      byte[] input = global(sequence(48, 71));
      System.arraycopy(fixture.client.token, 0, input, 7, 32);
      session.authenticate(input, (short) 7);
      byte[] digest = (byte[]) privateField(resources, "tokenDigest");
      Object hash = privateField(resources, "tokenHash");
      Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(digest));
      byte[] expected = java.security.MessageDigest.getInstance("SHA-256").digest(
        fixture.client.token
      );
      Assertions.assertArrayEquals(expected, digest);

      input[7] ^= 1;
      assertStatus(0x6982, () -> session.authenticate(input, (short) 7));
      assertStatus(0x6982, () -> session.list((short) 0));
      Assertions.assertFalse(Arrays.equals(expected, digest));
      input[7] ^= 1;
      for (short offset : new short[] { -1, 17, 32767 }) {
        session.authenticate(input, (short) 7);
        assertStatus(0x6A80, () -> session.authenticate(input, offset));
        assertStatus(0x6982, () -> session.list((short) 0));
      }
      session.authenticate(input, (short) 7);
      assertStatus(0x6A80, () -> session.authenticate(input));
      assertStatus(0x6982, () -> session.list((short) 0));
      session.authenticate(input, (short) 7);
      Assertions.assertSame(digest, privateField(resources, "tokenDigest"));
      Assertions.assertArrayEquals(expected, digest);

      Monoid independent = fixture.connect(true);
      Assertions.assertNotSame(session, independent);
      Assertions.assertSame(
        resources,
        privateField(privateField(independent, "safe"), "appletGrants")
      );
      Assertions.assertSame(hash, privateField(resources, "tokenHash"));
      Assertions.assertSame(digest, privateField(resources, "tokenDigest"));
      assertStatus(0x6982, () -> independent.authenticate(global(new byte[32])));
      assertStatus(0x6982, () -> independent.list((short) 0));
      Assertions.assertEquals(0, session.list((short) 0).getCount());
      byte[] beforeReset = digest.clone();
      fixture.card.reset();
      Assertions.assertArrayEquals(beforeReset, digest);
      Monoid afterReset = fixture.connectReusable(true);
      Assertions.assertNotSame(session, afterReset);
      Assertions.assertSame(hash, privateField(resources, "tokenHash"));
      Assertions.assertSame(digest, privateField(resources, "tokenDigest"));
      Assertions.assertArrayEquals(expected, digest);
      assertStatus(0x6982, () -> session.authenticate(global(fixture.client.token)));
      assertStatus(0x6982, () -> independent.authenticate(global(fixture.client.token)));
    }
  }

  @Test
  public void tokenValidationResourcesAreDiscardedOnFactoryResetAndNeverCrossSafeInstances()
    throws Exception {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid initial = fixture.connectReusable(true);
      Object resources = privateField(privateField(initial, "safe"), "appletGrants");
      Object hash = privateField(resources, "tokenHash");
      Object digest = privateField(resources, "tokenDigest");
      fixture.manage(0xFF, fields());
      Assertions.assertNull(privateField(resources, "tokenHash"));
      Assertions.assertNull(privateField(resources, "tokenDigest"));
      fixture.card.success(0x22, fields("pin", "888888", "secret", true));
      fixture.grant(null);
      Monoid reset = fixture.connectReusable(true);
      Assertions.assertSame(resources, privateField(privateField(reset, "safe"), "appletGrants"));
      Assertions.assertNotSame(hash, privateField(resources, "tokenHash"));
      Assertions.assertNotSame(digest, privateField(resources, "tokenDigest"));
      assertStatus(0x6982, () -> initial.authenticate(global(fixture.client.token)));

      hash = privateField(resources, "tokenHash");
      digest = privateField(resources, "tokenDigest");
      fixture.card.reset();
      fixture.card.reinstallMonoid();
      fixture.grant(null);
      Monoid replacement = fixture.connectReusable(true);
      Object nextResources = privateField(privateField(replacement, "safe"), "appletGrants");
      Assertions.assertNotSame(resources, nextResources);
      Assertions.assertNotSame(hash, privateField(nextResources, "tokenHash"));
      Assertions.assertNotSame(digest, privateField(nextResources, "tokenDigest"));
      assertStatus(0x6982, () -> reset.authenticate(global(fixture.client.token)));
    }
  }

  @Test
  public void rangedDataSnapshotsOwnTheirBindingAndTrackLiveItemChanges() {
    try (Fixture fixture = new Fixture()) {
      byte[] key = sequence(32, 13);
      byte[] stored = sequence(227, 41);
      byte[] storedIndex = index(0xF101, 1);
      fixture.card.create(storedIndex, key, null, stored, false);
      fixture.grant(null);
      Monoid session = fixture.connectReusable(true);
      byte[] buffer = global(new byte[64]);
      System.arraycopy(storedIndex, 0, buffer, 7, 10);
      System.arraycopy(key, 0, buffer, 20, 32);
      SafeDataShareable snapshot = session.getData(
        buffer,
        (short) 7,
        buffer,
        (short) 20,
        (short) 32
      );
      Arrays.fill(buffer, (byte) 0);
      Assertions.assertEquals(stored.length, snapshot.getLength());
      Assertions.assertArrayEquals(stored, read(snapshot));

      SafeItemShareable other = session.create(index(0xF101, 2), null, null, new Data(2), false);
      Assertions.assertArrayEquals(stored, read(snapshot));
      other.remove();
      Assertions.assertEquals(stored.length, snapshot.getLength());

      SafeItemShareable item = session.get(storedIndex);
      item.setData(new Data(3));
      assertStatus(0x6985, snapshot::getLength);
      SafeDataShareable replacement = session.getData(
        storedIndex,
        (short) 0,
        global(key),
        (short) 0,
        (short) 32
      );
      Assertions.assertArrayEquals(new byte[] { 3 }, read(replacement));
      item.remove();
      session.create(storedIndex, global(key), null, new Data(4), false);
      assertStatus(0x6985, replacement::getLength);
      assertStatus(0x6985, () -> replacement.read((short) 0, buffer, (short) 0, (short) 1));
    }
  }

  @Test
  public void rangedDataSnapshotsRequireExactKeysReadableDataAndCurrentAuthorization() {
    try (Fixture fixture = new Fixture()) {
      fixture.card.create(index(0xF101, 1), null, null, new byte[] { 1 }, false);
      fixture.card.create(index(0xF101, 2), new byte[] { 2 }, null, new byte[] { 2 }, true);
      fixture.grant(null);
      Monoid session = fixture.connectReusable(true);
      byte[] first = index(0xF101, 1);
      SafeDataShareable snapshot = session.getData(first, (short) 0, null, (short) 0, (short) 0);
      Assertions.assertArrayEquals(new byte[] { 1 }, read(snapshot));
      Assertions.assertNull(
        session.getData(first, (short) 0, global(new byte[0]), (short) 0, (short) 0)
      );
      Assertions.assertNull(
        session.getData(index(0xF101, 3), (short) 0, null, (short) 0, (short) 0)
      );
      assertStatus(0x6982, () ->
        session.getData(index(0xF101, 2), (short) 0, null, (short) 0, (short) 0)
      );
      assertStatus(0x6982, () ->
        session.getData(index(0xF103, 1), (short) 0, null, (short) 0, (short) 0)
      );
      for (short offset : new short[] { -1, 1, 32767 }) {
        assertStatus(0x6A80, () -> session.getData(first, offset, null, (short) 0, (short) 0));
      }
      assertStatus(0x6A80, () -> session.getData(first, (short) 0, null, (short) 1, (short) 0));
      assertStatus(0x6A80, () -> session.getData(first, (short) 0, first, (short) 0, (short) 11));
      session.get(first).setSecret(true);
      assertStatus(0x6982, snapshot::getLength);
      assertStatus(0x6982, () -> session.getData(first, (short) 0, null, (short) 0, (short) 0));
      fixture.manage(0x52, fields("aid", AppletTest.aidBytes(CLIENT_AID)));
      fixture.card.simulator.selectApplet(CLIENT_AID);
      assertStatus(0x6982, () ->
        session.getData(index(0xF101, 3), (short) 0, null, (short) 0, (short) 0)
      );
    }
  }

  @Test
  public void currentSessionValidatesOldSnapshotsWithoutRevivingTheirResetSession()
    throws Exception {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid initial = fixture.connectReusable(true);
      SafeDataShareable snapshot = initial
        .create(index(0xF101, 1), null, null, new Data(7), false)
        .getData();
      Assertions.assertTrue(initial.isDataCurrent(snapshot));
      Object[] binding = (Object[]) privateField(snapshot, "session");
      Assertions.assertEquals(JCSystem.CLEAR_ON_RESET, JCSystem.isTransient(binding));
      Assertions.assertNotNull(binding[0]);
      fixture.card.reset();
      Assertions.assertNull(binding[0]);

      Monoid current = fixture.connectReusable(false);
      assertStatus(0x6982, () -> current.isDataCurrent(snapshot));
      assertStatus(0x6982, () -> current.isDataCurrent(null));
      current.authenticate(global(fixture.client.token));
      Assertions.assertTrue(current.isDataCurrent(snapshot));
      assertStatus(0x6982, snapshot::getLength);
      assertStatus(0x6982, () ->
        snapshot.read((short) 0, global(new byte[1]), (short) 0, (short) 1)
      );
      assertStatus(0x6982, () -> initial.authenticate(global(fixture.client.token)));

      SafeItemShareable other = current.create(index(0xF101, 2), null, null, new Data(2), false);
      Assertions.assertTrue(current.isDataCurrent(snapshot));
      other.remove();
      Assertions.assertTrue(current.isDataCurrent(snapshot));
      SafeItemShareable item = current.get(index(0xF101, 1));
      item.setData(new Data(7));
      Assertions.assertFalse(current.isDataCurrent(snapshot));
      SafeDataShareable replaced = item.getData();
      Assertions.assertTrue(current.isDataCurrent(replaced));
      item.remove();
      Assertions.assertFalse(current.isDataCurrent(replaced));
      current.create(index(0xF101, 1), null, null, new Data(7), false);
      Assertions.assertFalse(current.isDataCurrent(replaced));
      assertStatus(0x6982, snapshot::getLength);
    }
  }

  @Test
  public void currentSnapshotChecksUseCurrentRightsAndNeverCallForeignData() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid initial = fixture.connectReusable(true);
      SafeDataShareable snapshot = initial
        .create(index(0xF101, 1), null, null, new Data(7), false)
        .getData();
      Data foreign = new Data(8);
      foreign.onLength = () -> Assertions.fail("Foreign data must not be called");
      foreign.onRead = () -> Assertions.fail("Foreign data must not be called");
      Assertions.assertFalse(initial.isDataCurrent(foreign));
      Assertions.assertFalse(initial.isDataCurrent(null));

      fixture.manage(
        0x51,
        fields(
          "aid",
          AppletTest.aidBytes(CLIENT_AID),
          "types",
          Arrays.asList(Arrays.asList((short) 0xF102, true))
        )
      );
      Monoid restricted = fixture.connectReusable(true);
      assertStatus(0x6982, () -> restricted.isDataCurrent(snapshot));
      assertStatus(0x6982, snapshot::getLength);

      fixture.grant(null);
      Monoid restored = fixture.connectReusable(true);
      Assertions.assertTrue(restored.isDataCurrent(snapshot));
      fixture.manage(0x52, fields("aid", AppletTest.aidBytes(CLIENT_AID)));
      fixture.card.simulator.selectApplet(CLIENT_AID);
      assertStatus(0x6982, () -> restored.isDataCurrent(snapshot));
      fixture.grant(null);
      Monoid current = fixture.connectReusable(true);
      Assertions.assertTrue(current.isDataCurrent(snapshot));
      current.get(index(0xF101, 1)).setSecret(true);
      assertStatus(0x6982, () -> current.isDataCurrent(snapshot));
    }
  }

  @Test
  public void snapshotChecksRejectDataFromAReplacedSafeInstance() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid initial = fixture.connectReusable(true);
      SafeDataShareable snapshot = initial
        .create(index(0xF101, 1), null, null, new Data(7), false)
        .getData();
      fixture.card.reset();
      fixture.card.reinstallMonoid();
      fixture.grant(null);
      Monoid current = fixture.connectReusable(true);
      current.create(index(0xF101, 1), null, null, new Data(7), false);
      Assertions.assertFalse(current.isDataCurrent(snapshot));
      assertStatus(0x6982, snapshot::getLength);
    }
  }

  @Test
  public void rangedReadsConsumeIndexAndKeyBeforeOverlappingOutput() {
    try (Fixture fixture = new Fixture()) {
      byte[] key = sequence(32, 13);
      byte[] stored = sequence(227, 41);
      byte[] storedIndex = index(0xF101, 1);
      fixture.card.create(storedIndex, key, null, stored, false);
      fixture.grant(null);
      Monoid session = fixture.connectReusable(true);
      byte[] buffer = global(new byte[133]);
      System.arraycopy(storedIndex, 0, buffer, 7, 10);
      System.arraycopy(key, 0, buffer, 20, 32);
      Assertions.assertEquals(
        227,
        session.readData(
          buffer,
          (short) 7,
          buffer,
          (short) 20,
          (short) 32,
          buffer,
          (short) 0,
          (short) 133
        )
      );
      Assertions.assertArrayEquals(Arrays.copyOf(stored, 133), buffer);

      System.arraycopy(storedIndex, 0, buffer, 7, 10);
      System.arraycopy(key, 0, buffer, 20, 32);
      buffer[20] ^= 1;
      byte[] unchanged = buffer.clone();
      Assertions.assertEquals(
        -1,
        session.readData(
          buffer,
          (short) 7,
          buffer,
          (short) 20,
          (short) 32,
          buffer,
          (short) 0,
          (short) 133
        )
      );
      Assertions.assertArrayEquals(unchanged, buffer);
      assertStatus(0x6A80, () ->
        session.readData(
          buffer,
          (short) 124,
          buffer,
          (short) 20,
          (short) 32,
          buffer,
          (short) 0,
          (short) 133
        )
      );
      assertStatus(0x6A80, () ->
        session.readData(
          buffer,
          (short) 7,
          buffer,
          (short) 102,
          (short) 32,
          buffer,
          (short) 0,
          (short) 133
        )
      );
      assertStatus(0x6A80, () ->
        session.readData(
          buffer,
          (short) 7,
          null,
          (short) 1,
          (short) 0,
          buffer,
          (short) 0,
          (short) 133
        )
      );
      assertStatus(0x6A80, () -> session.readData(buffer, null, buffer, (short) 0, (short) 1));
      Assertions.assertArrayEquals(unchanged, buffer);
      fixture.grant(null);
      fixture.card.simulator.selectApplet(CLIENT_AID);
      assertStatus(0x6982, () ->
        session.readData(
          buffer,
          (short) 7,
          buffer,
          (short) 20,
          (short) 32,
          buffer,
          (short) 0,
          (short) 133
        )
      );
    }
  }

  @Test
  public void rangedEnumerationConsumesKeyBeforeOutputsAndRejectsInvalidSlicesBeforeAdvancing() {
    try (Fixture fixture = new Fixture()) {
      byte[] key = sequence(32, 13);
      byte[] stored = sequence(40, 51);
      byte[] storedIndex = index(0xF101, 1);
      fixture.card.create(storedIndex, key, null, stored, false);
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      SafeItemIteratorShareable iterator = session.list((short) 0xF101);
      byte[] buffer = global(new byte[133]);
      System.arraycopy(key, 0, buffer, 10, 32);
      byte[] unchanged = buffer.clone();
      assertStatus(0x6A80, () ->
        iterator.nextData(
          buffer,
          (short) 102,
          (short) 32,
          buffer,
          (short) 0,
          buffer,
          (short) 10,
          (short) 100
        )
      );
      assertStatus(0x6A80, () ->
        iterator.nextData(
          null,
          (short) 0,
          (short) 1,
          buffer,
          (short) 0,
          buffer,
          (short) 10,
          (short) 100
        )
      );
      Assertions.assertArrayEquals(unchanged, buffer);
      Assertions.assertEquals(
        40,
        iterator.nextData(
          buffer,
          (short) 10,
          (short) 32,
          buffer,
          (short) 0,
          buffer,
          (short) 10,
          (short) 100
        )
      );
      Assertions.assertArrayEquals(storedIndex, Arrays.copyOf(buffer, 10));
      Assertions.assertArrayEquals(stored, Arrays.copyOfRange(buffer, 10, 50));
      unchanged = buffer.clone();
      Assertions.assertEquals(
        -1,
        iterator.nextData(
          buffer,
          (short) 10,
          (short) 32,
          buffer,
          (short) 0,
          buffer,
          (short) 10,
          (short) 100
        )
      );
      Assertions.assertArrayEquals(unchanged, buffer);
    }
  }

  @Test
  public void rangedDerivationSupportsOverlappingMinimumAPDUWindowAndRejectsInvalidSlices()
    throws Exception {
    try (Fixture fixture = new Fixture()) {
      byte[] seed = sequence(64, 1);
      byte[] domain = new byte[] { 4, 2 };
      byte[] seedIndex = fixture.card.create("seed", null, null, seed, true);
      fixture.grant(fields("index", seedIndex, "domain", domain));
      Monoid session = fixture.connectReusable(true);
      byte[] context = sequence(78, 31);
      byte[] digest = sequence(32, 71);
      byte[] publicKey = referencePublicKey(seed, domain, context);
      byte[] buffer = global(new byte[133]);
      System.arraycopy(context, 0, buffer, 3, context.length);
      Assertions.assertEquals(
        65,
        session.getMonoid001PublicKey(buffer, (short) 3, (short) 78, buffer, (short) 0)
      );
      Assertions.assertArrayEquals(publicKey, Arrays.copyOf(buffer, 65));
      byte[] frame = privateFrame(session);
      System.arraycopy(context, 0, buffer, 3, context.length);
      System.arraycopy(digest, 0, buffer, 81, digest.length);
      Assertions.assertEquals(
        64,
        session.signMonoid001ECDSADigest(
          buffer,
          (short) 3,
          (short) 78,
          buffer,
          (short) 81,
          buffer,
          (short) 0
        )
      );
      assertSignature(publicKey, digest, Arrays.copyOf(buffer, 64));
      Assertions.assertSame(frame, privateFrame(session));

      byte[] unchanged = buffer.clone();
      for (short[] range : new short[][] { { -1, 78 }, { 56, 78 }, { 0, -1 }, { 1, 32767 } }) {
        assertStatus(0x6A80, () ->
          session.getMonoid001PublicKey(buffer, range[0], range[1], buffer, (short) 0)
        );
        assertStatus(0x6A80, () ->
          session.signMonoid001ECDSADigest(
            buffer,
            range[0],
            range[1],
            buffer,
            (short) 81,
            buffer,
            (short) 0
          )
        );
      }
      assertStatus(0x6A80, () ->
        session.signMonoid001ECDSADigest(
          buffer,
          (short) 3,
          (short) 78,
          buffer,
          (short) 102,
          buffer,
          (short) 0
        )
      );
      assertStatus(0x6A80, () ->
        session.signMonoid001ECDSADigest(global(context), buffer, buffer, (short) 0)
      );
      Assertions.assertArrayEquals(unchanged, buffer);
      fixture.card.simulator.installApplet(OTHER_AID, AppletGrantClient.class);
      try {
        fixture.card.simulator.selectApplet(OTHER_AID);
        assertStatus(0x6982, () ->
          session.getMonoid001PublicKey(buffer, (short) 3, (short) 78, buffer, (short) 0)
        );
        assertStatus(0x6982, () -> session.authenticate(buffer, (short) 0));
      } finally {
        fixture.card.simulator.selectApplet(CLIENT_AID);
        fixture.card.simulator.deleteApplet(OTHER_AID);
      }
      assertStatus(0x6982, () ->
        session.signMonoid001ECDSADigest(
          buffer,
          (short) 3,
          (short) 78,
          buffer,
          (short) 81,
          buffer,
          (short) 0
        )
      );
      Assertions.assertArrayEquals(unchanged, buffer);
    }
  }

  @Test
  public void storageCallbacksUseBoundedGlobalWindowsAndCommittedDataDoesNotAliasSource() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      for (int length : new int[] { 227, 300 }) {
        byte[] stored = sequence(length, 41);
        byte[] storedIndex = index(0xF101, length);
        byte[] key = global(new byte[] { 7 });
        byte[] alias = global(new byte[] { 8 });
        int[] copied = { 0 };
        int[] callbacks = { 0 };
        SafeDataShareable source = new SafeDataShareable() {
          @Override
          public short getLength() {
            return (short) stored.length;
          }

          @Override
          public void read(short offset, byte[] buffer, short bufferOffset, short count) {
            Assertions.assertEquals(Math.min(256, stored.length - offset), buffer.length);
            Assertions.assertEquals(copied[0], offset);
            Assertions.assertEquals(0, bufferOffset);
            short outerRemaining = (short) Math.min(
              stored.length - copied[0],
              256 - (copied[0] % 256)
            );
            Assertions.assertEquals(Math.min(outerRemaining, buffer.length), count);
            key[0] = 99;
            alias[0] = 99;
            System.arraycopy(stored, offset, buffer, bufferOffset, count);
            copied[0] += count;
            callbacks[0]++;
          }
        };
        SafeItemShareable item = session.create(storedIndex, key, alias, source, false);
        Assertions.assertEquals(length, copied[0]);
        int window = 256;
        int expectedCallbacks = 0;
        for (int offset = 0; offset < length; offset += 256) {
          expectedCallbacks += (Math.min(256, length - offset) + window - 1) / window;
        }
        Assertions.assertEquals(expectedCallbacks, callbacks[0]);
        Arrays.fill(stored, (byte) 0x55);
        Assertions.assertArrayEquals(new byte[] { 7 }, item.getKey());
        Assertions.assertArrayEquals(new byte[] { 8 }, item.getAlias());
        Assertions.assertArrayEquals(sequence(length, 41), read(item.getData()));
      }
    }
  }

  @Test
  public void customCreationCopiesAliasedMetadataBeforeTheSourceMutatesIt() throws Exception {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      byte[] data = sequence(64, 17);
      byte[] storedIndex = index(0xF101, 1);
      byte[] window = global(new byte[64]);
      Arrays.fill(window, (byte) 0x37);
      byte[] expected = window.clone();
      SafeDataShareable source = new SafeDataShareable() {
        @Override
        public short getLength() {
          return (short) data.length;
        }

        @Override
        public void read(short offset, byte[] buffer, short bufferOffset, short length) {
          Assertions.assertNotSame(window, buffer);
          Arrays.fill(window, (byte) 0x55);
          System.arraycopy(data, offset, buffer, bufferOffset, length);
        }
      };
      SafeItemShareable item = session.create(storedIndex, window, window, source, true);
      Assertions.assertArrayEquals(storedIndex, item.getIndex());
      Assertions.assertArrayEquals(expected, item.getKey());
      Assertions.assertArrayEquals(expected, item.getAlias());
      Assertions.assertFalse(Arrays.equals(expected, window));
    }
  }

  @Test
  public void reusableAcquisitionClearsAuthenticationWithoutChangingIndependentSessions() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid independent = fixture.connect(true);
      Monoid reusable = fixture.connectReusable(true);
      Assertions.assertNotSame(independent, reusable);
      SafeItemShareable item = reusable.create(index(0xF101, 1), null, null, new Data(7), false);
      SafeDataShareable data = item.getData();
      SafeItemIteratorShareable iterator = reusable.list((short) 0);

      Monoid again = fixture.connectReusable(false);
      Assertions.assertSame(reusable, again);
      assertStatus(0x6982, () -> reusable.list((short) 0));
      assertStatus(0x6982, item::getIndex);
      assertStatus(0x6982, data::getLength);
      assertStatus(0x6982, iterator::getCount);
      Assertions.assertEquals(1, independent.list((short) 0).getCount());

      assertStatus(0x6982, () -> again.authenticate(global(new byte[32])));
      assertStatus(0x6982, item::getIndex);
      again.authenticate(global(fixture.client.token));
      Assertions.assertEquals(7, read(data)[0]);
      Assertions.assertEquals(1, iterator.getCount());

      Monoid anotherIndependent = fixture.connect(false);
      Assertions.assertNotSame(independent, anotherIndependent);
      Assertions.assertNotSame(reusable, anotherIndependent);
      assertStatus(0x6982, () -> anotherIndependent.list((short) 0));
      Assertions.assertEquals(1, reusable.list((short) 0).getCount());
      Assertions.assertNull(JCSystem.getAppletShareableInterfaceObject(MONOID_AID, (byte) 2));
      Assertions.assertEquals(1, reusable.list((short) 0).getCount());
    }
  }

  @Test
  public void reusableSessionsAndHandlesNeverReviveAfterResetOrGrantReplacement() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid initial = fixture.connectReusable(true);
      SafeItemShareable item = initial.create(index(0xF101, 1), null, null, new Data(7), false);
      SafeDataShareable data = item.getData();
      SafeItemIteratorShareable iterator = initial.list((short) 0);
      fixture.card.reset();
      Monoid afterReset = fixture.connectReusable(true);
      Assertions.assertNotSame(initial, afterReset);
      assertStatus(0x6982, () -> initial.authenticate(global(fixture.client.token)));
      assertStatus(0x6982, item::getIndex);
      assertStatus(0x6982, data::getLength);
      assertStatus(0x6982, iterator::getCount);

      SafeItemShareable beforeReplacement = afterReset.get(index(0xF101, 1));
      SafeDataShareable beforeReplacementData = beforeReplacement.getData();
      // Replacing even identical rights/token creates a different immutable grant.
      fixture.grant(null);
      Monoid replacement = fixture.connectReusable(true);
      Assertions.assertNotSame(afterReset, replacement);
      assertStatus(0x6982, () -> afterReset.authenticate(global(fixture.client.token)));
      assertStatus(0x6982, beforeReplacement::getIndex);
      assertStatus(0x6982, beforeReplacementData::getLength);
      Assertions.assertEquals(7, read(replacement.get(index(0xF101, 1)).getData())[0]);

      fixture.manage(0x52, fields("aid", AppletTest.aidBytes(CLIENT_AID)));
      fixture.card.simulator.selectApplet(CLIENT_AID);
      Assertions.assertNull(JCSystem.getAppletShareableInterfaceObject(MONOID_AID, (byte) 1));
      assertStatus(0x6982, () -> replacement.authenticate(global(fixture.client.token)));
      fixture.grant(null);
      Monoid restored = fixture.connectReusable(true);
      Assertions.assertNotSame(replacement, restored);
      assertStatus(0x6982, () -> replacement.list((short) 0));

      fixture.card.simulator.selectApplet(MONOID_AID);
      fixture.card.success(0xFF, fields());
      fixture.card.simulator.selectApplet(CLIENT_AID);
      Assertions.assertNull(JCSystem.getAppletShareableInterfaceObject(MONOID_AID, (byte) 1));
      assertStatus(0x6982, () -> restored.authenticate(global(fixture.client.token)));
      fixture.card.simulator.selectApplet(MONOID_AID);
      fixture.card.success(0x22, fields("pin", "888888", "secret", true));
      fixture.grant(null);
      Monoid afterFactoryReset = fixture.connectReusable(true);
      Assertions.assertNotSame(restored, afterFactoryReset);
      assertStatus(0x6982, () -> restored.authenticate(global(fixture.client.token)));
    }
  }

  @Test
  public void reusableCacheNeverRebindsAnObjectToAnotherCaller() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid first = fixture.connectReusable(true);
      SafeItemShareable item = first.create(index(0xF101, 1), null, null, new Data(7), false);
      SafeDataShareable data = item.getData();
      SafeItemIteratorShareable iterator = first.list((short) 0);
      fixture.card.simulator.installApplet(OTHER_AID, AppletGrantClient.class);
      AppletGrantClient other = AppletGrantClient.installed;
      try {
        fixture.manage(
          0x51,
          fields(
            "aid",
            AppletTest.aidBytes(OTHER_AID),
            "types",
            Arrays.asList(Arrays.asList((short) 0xF101, true))
          )
        );
        fixture.card.simulator.selectApplet(OTHER_AID);
        Monoid second = (Monoid) JCSystem.getAppletShareableInterfaceObject(MONOID_AID, (byte) 1);
        Assertions.assertNotSame(first, second);
        assertStatus(0x6982, () -> second.authenticate(global(fixture.client.token)));
        second.authenticate(global(other.token));
        assertStatus(0x6982, () -> first.list((short) 0));
        assertStatus(0x6982, item::getIndex);
        assertStatus(0x6982, data::getLength);
        assertStatus(0x6982, iterator::getCount);

        Monoid firstAgain = fixture.connectReusable(true);
        Assertions.assertNotSame(first, firstAgain);
        Assertions.assertNotSame(second, firstAgain);
        Assertions.assertEquals(1, first.list((short) 0).getCount());
        Assertions.assertEquals(7, read(data)[0]);
        assertStatus(0x6982, () -> second.authenticate(global(other.token)));
      } finally {
        fixture.card.simulator.deleteApplet(OTHER_AID);
      }
    }
  }

  @Test
  public void reacquiringReusableSessionDuringCallbackCannotPublishWithoutAuthentication() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connectReusable(true);
      Data source = new Data(7);
      source.onRead = () ->
        Assertions.assertSame(
          session,
          JCSystem.getAppletShareableInterfaceObject(MONOID_AID, (byte) 1)
        );
      assertStatus(0x6982, () -> session.create(index(0xF101, 1), null, null, source, false));
      session.authenticate(global(fixture.client.token));
      Assertions.assertNull(session.get(index(0xF101, 1)));
      source.onRead = () -> assertStatus(0x6985, () -> session.list((short) 0));
      session.create(index(0xF101, 1), null, null, source, false);
      Assertions.assertEquals(7, read(session.get(index(0xF101, 1)).getData())[0]);
    }
  }

  @Test
  public void reusableDerivationStillUsesCurrentContextAndReplacementDomain() throws Exception {
    try (Fixture fixture = new Fixture()) {
      byte[] seed = sequence(64, 21);
      byte[] domain = new byte[] { 1 };
      byte[] seedIndex = fixture.card.create("seed", null, null, seed, true);
      fixture.grant(fields("index", seedIndex, "domain", domain));
      Monoid first = fixture.connectReusable(true);
      byte[] context = global(sequence(79, 31));
      byte[] output = global(new byte[65]);
      byte[] digest = global(sequence(32, 51));
      byte[] signature = global(new byte[64]);
      first.getMonoid001PublicKey(context, output, (short) 0);
      Assertions.assertArrayEquals(referencePublicKey(seed, domain, context), output);

      Monoid again = fixture.connectReusable(true);
      Assertions.assertSame(first, again);
      again.signMonoid001ECDSADigest(context, digest, signature, (short) 0);
      assertSignature(referencePublicKey(seed, domain, context), digest, signature);
      context[0] ^= 1;
      again.getMonoid001PublicKey(context, output, (short) 0);
      Assertions.assertArrayEquals(referencePublicKey(seed, domain, context), output);
      again.signMonoid001ECDSADigest(context, digest, signature, (short) 0);
      assertSignature(referencePublicKey(seed, domain, context), digest, signature);

      byte[] nextDomain = new byte[] { 2 };
      fixture.grant(fields("index", seedIndex, "domain", nextDomain));
      Monoid replacement = fixture.connectReusable(true);
      Assertions.assertNotSame(first, replacement);
      assertStatus(0x6982, () -> first.getMonoid001PublicKey(context, output, (short) 0));
      replacement.getMonoid001PublicKey(context, output, (short) 0);
      Assertions.assertArrayEquals(referencePublicKey(seed, nextDomain, context), output);
    }
  }

  @Test
  public void sessionsAndEveryReturnedHandleAreBoundToTheActualCaller() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      SafeItemShareable item = session.create(index(0xF101, 1), null, null, new Data(7), false);
      SafeDataShareable data = item.getData();
      SafeItemIteratorShareable iterator = session.list((short) 0);
      fixture.card.simulator.installApplet(OTHER_AID, AppletGrantClient.class);
      fixture.card.simulator.selectApplet(OTHER_AID);
      Assertions.assertNull(JCSystem.getAppletShareableInterfaceObject(MONOID_AID, (byte) 0));
      assertStatus(0x6982, () -> session.list((short) 0));
      assertStatus(0x6982, item::getIndex);
      assertStatus(0x6982, data::getLength);
      assertStatus(0x6982, iterator::next);
      fixture.card.simulator.selectApplet(CLIENT_AID);
      Assertions.assertEquals(1, iterator.getCount());
      Assertions.assertEquals(7, read(data)[0]);
      fixture.card.simulator.deleteApplet(OTHER_AID);
    }
  }

  @Test
  public void typeCategoryAndPrefixFiltersNeverExpandAnExactGrant() {
    try (Fixture fixture = new Fixture()) {
      fixture.card.create(index(0xF101, 1), new byte[] { 4, 2 }, "first", new byte[] { 1 }, false);
      fixture.card.create(index(0xF102, 2), new byte[] { 4, 3 }, null, new byte[] { 2 }, false);
      fixture.card.create(index(0xF103, 3), new byte[] { 4, 2 }, null, new byte[] { 3 }, false);
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      Assertions.assertEquals(2, session.list((short) 0xF100).getCount());
      Assertions.assertEquals(1, session.list((short) 0, global(new byte[] { 4, 2 })).getCount());
      Assertions.assertEquals(0, session.list((short) 0xF103).getCount());
      Assertions.assertNull(session.get(index(0xF101, 9)));
      assertStatus(0x6982, () -> session.get(index(0xF103, 3)));
      assertStatus(0x6982, () -> session.get(index(0x0302, 1)));
      SafeItemShareable readOnly = session.get(index(0xF102, 2));
      Assertions.assertArrayEquals(new byte[] { 2 }, read(readOnly.getData()));
      assertStatus(0x6982, () -> readOnly.setAlias(global(new byte[] { 1 })));
      assertStatus(0x6982, () -> readOnly.setData(new Data(3)));
      assertStatus(0x6982, () -> readOnly.setSecret(true));
      assertStatus(0x6982, readOnly::remove);
      assertStatus(0x6982, () -> session.create(index(0xF102, 4), null, null, new Data(4), false));
    }
  }

  @Test
  public void secretProtectionAlsoAppliesToPreviouslyReturnedReaders() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      SafeItemShareable item = session.create(index(0xF101, 1), null, null, new Data(7), false);
      SafeDataShareable prior = item.getData();
      item.setSecret(true);
      Assertions.assertTrue(item.isSecret());
      assertStatus(0x6982, item::getData);
      assertStatus(0x6982, prior::getLength);
      assertStatus(0x6982, () -> prior.read((short) 0, global(new byte[1]), (short) 0, (short) 1));
      assertStatus(0x6985, () -> item.setSecret(false));
      item.setData(new Data(8));
      Assertions.assertTrue(item.isSecret());
      item.setData(new Data(9), false);
      Assertions.assertFalse(item.isSecret());
      Assertions.assertArrayEquals(new byte[] { 9 }, read(item.getData()));
      assertStatus(0x6985, prior::getLength);
    }
  }

  @Test
  public void boundedIndicesReturnFullCountAndPreservePrefixTypeAndGrantFilters() {
    try (Fixture fixture = new Fixture()) {
      fixture.card.create(index(0xF101, 1), new byte[] { 4, 2 }, null, new byte[] { 1 }, false);
      fixture.card.create(index(0xF102, 2), new byte[] { 4, 3 }, null, new byte[] { 2 }, true);
      fixture.card.create(index(0xF101, 3), new byte[] { 4, 2, 1 }, null, new byte[] { 3 }, false);
      fixture.card.create(index(0xF103, 4), new byte[] { 4, 2 }, null, new byte[] { 4 }, false);
      fixture.card.create(index(0xF101, 5), null, null, new byte[] { 5 }, false);
      fixture.grant(null);
      Monoid session = fixture.connectReusable(true);
      byte[] window = global(sequence(64, 71));
      window[3] = 4;
      byte[] original = window.clone();
      Assertions.assertEquals(
        3,
        session.listIndices(
          (short) 0xF100,
          window,
          (short) 3,
          (short) 1,
          window,
          (short) 12,
          (short) 2
        )
      );
      byte[] expected = original.clone();
      System.arraycopy(index(0xF101, 1), 0, expected, 12, 10);
      System.arraycopy(index(0xF102, 2), 0, expected, 22, 10);
      Assertions.assertArrayEquals(expected, window);
      Assertions.assertEquals(
        4,
        session.listIndices(
          (short) 0,
          null,
          (short) 0,
          (short) 0,
          window,
          (short) window.length,
          (short) 0
        )
      );
      Assertions.assertArrayEquals(expected, window);
      window[4] = 2;
      Assertions.assertEquals(
        2,
        session.listIndices((short) 0, window, (short) 3, (short) 2, window, (short) 12, (short) 4)
      );
      Assertions.assertArrayEquals(index(0xF101, 3), Arrays.copyOfRange(window, 22, 32));
      Assertions.assertEquals(
        0,
        session.listIndices(
          (short) 0xF103,
          null,
          (short) 0,
          (short) 0,
          window,
          (short) 0,
          (short) 4
        )
      );
      // Only indices are exposed; the existing readable-data rule still rejects the secret.
      assertStatus(0x6982, () ->
        session.readData(
          index(0xF102, 2),
          global(new byte[] { 4, 3 }),
          window,
          (short) 0,
          (short) 1
        )
      );
    }
  }

  @Test
  public void boundedIndicesRejectInvalidAndOverlappingRangesBeforeWriting() {
    try (Fixture fixture = new Fixture()) {
      fixture.card.create(index(0xF101, 1), new byte[] { 4 }, null, new byte[] { 1 }, false);
      fixture.grant(null);
      Monoid session = fixture.connectReusable(true);
      byte[] window = global(sequence(64, 41));
      byte[] original = window.clone();
      for (short[] range : new short[][] {
        { -1, 1 },
        { 0, -1 },
        { 55, 1 },
        { 0, 3277 },
        { 32767, 1 },
      }) {
        assertStatus(0x6A80, () ->
          session.listIndices((short) 0, null, (short) 0, (short) 0, window, range[0], range[1])
        );
      }
      assertStatus(0x6A80, () ->
        session.listIndices((short) 0, null, (short) 1, (short) 0, window, (short) 0, (short) 1)
      );
      assertStatus(0x6A80, () ->
        session.listIndices((short) 0, window, (short) 63, (short) 2, window, (short) 0, (short) 1)
      );
      assertStatus(0x6A80, () ->
        session.listIndices((short) 0, window, (short) 3, (short) 2, window, (short) 4, (short) 1)
      );
      assertStatus(0x6A80, () ->
        session.listIndices((short) 0, window, (short) 3, (short) 2, window, (short) 0, (short) 1)
      );
      Assertions.assertArrayEquals(original, window);
    }
  }

  @Test
  public void directReadsReturnTotalLengthAndMatchKeysExactlyWithoutChangingOtherBytes() {
    try (Fixture fixture = new Fixture()) {
      byte[] data = sequence(300, 17);
      byte[] key = global(new byte[] { 4, 2 });
      fixture.card.create(index(0xF102, 1), key, null, data, false);
      fixture.card.create(index(0xF101, 2), null, null, new byte[0], false);
      fixture.card.create(index(0xF101, 3), new byte[0], null, new byte[] { 7 }, false);
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      byte[] output = global(sequence(310, 91));
      byte[] expected = output.clone();
      System.arraycopy(data, 0, expected, 5, 100);
      Assertions.assertEquals(
        300,
        session.readData(index(0xF102, 1), key, output, (short) 5, (short) 100)
      );
      Assertions.assertArrayEquals(expected, output);
      Assertions.assertEquals(
        300,
        session.readData(index(0xF102, 1), key, output, (short) output.length, (short) 0)
      );
      Assertions.assertArrayEquals(expected, output);
      System.arraycopy(data, 0, expected, 5, data.length);
      Assertions.assertEquals(
        300,
        session.readData(index(0xF102, 1), key, output, (short) 5, (short) 305)
      );
      Assertions.assertArrayEquals(expected, output);

      for (byte[] wrong : new byte[][] {
        null,
        global(new byte[0]),
        global(new byte[] { 4 }),
        global(new byte[] { 4, 3 }),
      }) {
        Assertions.assertEquals(
          -1,
          session.readData(index(0xF102, 1), wrong, output, (short) 0, (short) 100)
        );
        Assertions.assertArrayEquals(expected, output);
      }
      Assertions.assertEquals(
        -1,
        session.readData(index(0xF101, 9), null, output, (short) 0, (short) 100)
      );
      Assertions.assertEquals(
        0,
        session.readData(index(0xF101, 2), null, output, (short) 0, (short) 100)
      );
      Assertions.assertEquals(
        -1,
        session.readData(index(0xF101, 2), global(new byte[0]), output, (short) 0, (short) 100)
      );
      Assertions.assertEquals(
        -1,
        session.readData(index(0xF101, 3), null, output, (short) 0, (short) 100)
      );
      Assertions.assertArrayEquals(expected, output);
      Assertions.assertEquals(
        1,
        session.readData(index(0xF101, 3), global(new byte[0]), output, (short) 0, (short) 1)
      );
      expected[0] = 7;
      Assertions.assertArrayEquals(expected, output);
    }
  }

  @Test
  public void directReadsValidateAllRangesAndSecretPermissionBeforeCopying() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      session.create(index(0xF101, 1), null, null, new Data(7), false);
      session.create(index(0xF101, 2), null, null, new Data(8), true);
      byte[] output = global(sequence(12, 71));
      byte[] original = output.clone();
      for (short[] range : new short[][] {
        { -1, 1 },
        { 0, -1 },
        { 12, 1 },
        { 1, 12 },
        { 32767, 1 },
        { 1, 32767 },
      }) {
        assertStatus(0x6A80, () ->
          session.readData(index(0xF101, 1), null, output, range[0], range[1])
        );
        Assertions.assertArrayEquals(original, output);
      }
      assertStatus(0x6A80, () ->
        session.readData(index(0xF101, 1), null, null, (short) 0, (short) 0)
      );
      assertStatus(0x6A80, () ->
        session.readData(global(new byte[9]), null, output, (short) 0, (short) 1)
      );
      assertStatus(0x6982, () ->
        session.readData(index(0xF103, 1), null, output, (short) 0, (short) 1)
      );
      assertStatus(0x6982, () ->
        session.readData(index(0xF101, 2), null, output, (short) 0, (short) 0)
      );
      assertStatus(0x6982, () ->
        session.readData(index(0xF101, 2), null, output, (short) 0, (short) 1)
      );
      Assertions.assertArrayEquals(original, output);
      Assertions.assertEquals(
        1,
        session.readData(index(0xF101, 1), null, output, (short) 0, (short) 1)
      );
    }
  }

  @Test
  public void directReadsObserveCurrentDataWhileLegacyReadersKeepSnapshotChecks() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      SafeItemShareable item = session.create(index(0xF101, 1), null, null, new Data(7), false);
      SafeDataShareable prior = item.getData();
      byte[] output = global(new byte[1]);
      Assertions.assertEquals(
        1,
        session.readData(index(0xF101, 1), null, output, (short) 0, (short) 1)
      );
      Assertions.assertEquals(7, output[0]);
      item.setData(new Data(8));
      assertStatus(0x6985, prior::getLength);
      Assertions.assertEquals(
        1,
        session.readData(index(0xF101, 1), null, output, (short) 0, (short) 1)
      );
      Assertions.assertEquals(8, output[0]);
      item.setSecret(true);
      assertStatus(0x6982, () ->
        session.readData(index(0xF101, 1), null, output, (short) 0, (short) 1)
      );
      Assertions.assertEquals(8, output[0]);
      item.remove();
      Assertions.assertEquals(
        -1,
        session.readData(index(0xF101, 1), null, output, (short) 0, (short) 1)
      );
    }
  }

  @Test
  public void directEnumerationReturnsRealIndicesAndPrefixesAndDoesNotWriteAtEnd() {
    try (Fixture fixture = new Fixture()) {
      byte[] key = global(new byte[] { 4, 2 });
      fixture.card.create(index(0xF101, 1), key, null, sequence(300, 11), false);
      fixture.card.create(index(0xF102, 2), key, null, new byte[0], false);
      fixture.card.create(index(0xF103, 3), key, null, new byte[] { 9 }, false);
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      SafeItemIteratorShareable iterator = session.list((short) 0xF100, key);
      Assertions.assertEquals(2, iterator.getCount());
      byte[] output = global(sequence(24, 71));
      byte[] expected = output.clone();
      System.arraycopy(index(0xF101, 1), 0, expected, 1, 10);
      System.arraycopy(sequence(300, 11), 0, expected, 13, 8);
      Assertions.assertEquals(
        300,
        iterator.nextData(key, output, (short) 1, output, (short) 13, (short) 8)
      );
      Assertions.assertArrayEquals(expected, output);
      System.arraycopy(index(0xF102, 2), 0, expected, 1, 10);
      Assertions.assertEquals(
        0,
        iterator.nextData(key, output, (short) 1, output, (short) 24, (short) 0)
      );
      Assertions.assertArrayEquals(expected, output);
      Assertions.assertEquals(
        -1,
        iterator.nextData(key, output, (short) 1, output, (short) 13, (short) 8)
      );
      Assertions.assertArrayEquals(expected, output);
    }
  }

  @Test
  public void directEnumerationRejectsMetadataMismatchAndSecretDataWithoutSkipping() {
    try (Fixture fixture = new Fixture()) {
      byte[] key = global(new byte[] { 4, 2 });
      fixture.card.create(index(0xF101, 1), new byte[] { 4, 2, 3 }, null, new byte[] { 1 }, false);
      fixture.card.create(index(0xF101, 2), key, null, new byte[] { 2 }, false);
      fixture.card.create(index(0xF102, 3), null, null, new byte[] { 3 }, true);
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      byte[] output = global(sequence(12, 61));
      byte[] original = output.clone();
      SafeItemIteratorShareable mismatched = session.list((short) 0xF101, key);
      assertStatus(0x6985, () ->
        mismatched.nextData(key, output, (short) 0, output, (short) 11, (short) 1)
      );
      Assertions.assertArrayEquals(original, output);
      SafeItemIteratorShareable nullMismatch = session.list((short) 0xF101, key);
      assertStatus(0x6985, () ->
        nullMismatch.nextData(null, output, (short) 0, output, (short) 11, (short) 1)
      );
      SafeItemIteratorShareable secret = session.list((short) 0xF102);
      assertStatus(0x6982, () ->
        secret.nextData(null, output, (short) 0, output, (short) 11, (short) 0)
      );
      Assertions.assertArrayEquals(original, output);
    }
  }

  @Test
  public void directEnumerationValidatesBothOutputRangesAndRejectsOverlap() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      session.create(index(0xF101, 1), null, null, new Data(7), false);
      byte[] output = global(sequence(12, 51));
      byte[] original = output.clone();
      SafeItemIteratorShareable iterator = session.list((short) 0);
      assertStatus(0x6A80, () ->
        iterator.nextData(null, output, (short) 3, output, (short) 11, (short) 1)
      );
      assertStatus(0x6A80, () ->
        iterator.nextData(null, output, (short) 0, output, (short) 12, (short) 1)
      );
      assertStatus(0x6A80, () ->
        iterator.nextData(null, output, (short) 0, output, (short) 0, (short) -1)
      );
      Assertions.assertArrayEquals(original, output);
      // Invalid ranges were rejected before advancing.
      Assertions.assertEquals(
        1,
        iterator.nextData(null, output, (short) 0, output, (short) 11, (short) 1)
      );
      Assertions.assertArrayEquals(index(0xF101, 1), Arrays.copyOfRange(output, 0, 10));
      Assertions.assertEquals(7, output[11]);
      System.arraycopy(original, 0, output, 0, original.length);
      SafeItemIteratorShareable overlapping = session.list((short) 0);
      assertStatus(0x6A80, () ->
        overlapping.nextData(null, output, (short) 0, output, (short) 9, (short) 1)
      );
      Assertions.assertArrayEquals(original, output);
    }
  }

  @Test
  public void directReadsAndEnumerationRetainCallerAuthenticationAndRevocationChecks() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connectReusable(true);
      session.create(index(0xF101, 1), null, null, new Data(7), false);
      SafeItemIteratorShareable iterator = session.list((short) 0);
      byte[] output = global(sequence(12, 41));
      byte[] original = output.clone();
      Runnable read = () -> session.readData(index(0xF101, 1), null, output, (short) 11, (short) 1);
      Runnable next = () ->
        iterator.nextData(null, output, (short) 0, output, (short) 11, (short) 1);
      Runnable list = () ->
        session.listIndices((short) 0, null, (short) 0, (short) 0, output, (short) 0, (short) 1);
      fixture.connectReusable(false);
      assertStatus(0x6982, read);
      assertStatus(0x6982, next);
      assertStatus(0x6982, list);
      session.authenticate(global(fixture.client.token));
      fixture.card.simulator.installApplet(OTHER_AID, AppletGrantClient.class);
      try {
        fixture.card.simulator.selectApplet(OTHER_AID);
        assertStatus(0x6982, read);
        assertStatus(0x6982, next);
        assertStatus(0x6982, list);
      } finally {
        fixture.card.simulator.selectApplet(CLIENT_AID);
        fixture.card.simulator.deleteApplet(OTHER_AID);
      }
      fixture.grant(null);
      fixture.card.simulator.selectApplet(CLIENT_AID);
      assertStatus(0x6982, read);
      assertStatus(0x6982, next);
      assertStatus(0x6982, list);
      Assertions.assertArrayEquals(original, output);
      Monoid replacement = fixture.connectReusable(true);
      SafeItemIteratorShareable beforeReset = replacement.list((short) 0);
      fixture.card.reset();
      fixture.card.simulator.selectApplet(CLIENT_AID);
      // Global arrays are reset-cleared too; seed a fresh sentinel before testing rejection.
      System.arraycopy(original, 0, output, 0, original.length);
      assertStatus(0x6982, () ->
        replacement.readData(index(0xF101, 1), null, output, (short) 11, (short) 1)
      );
      assertStatus(0x6982, () ->
        beforeReset.nextData(null, output, (short) 0, output, (short) 11, (short) 1)
      );
      assertStatus(0x6982, () ->
        replacement.listIndices((short) 0, null, (short) 0, (short) 0, output, (short) 0, (short) 1)
      );
      Assertions.assertArrayEquals(original, output);
    }
  }

  @Test
  public void directEnumerationRejectsDirectoryChangesBeforeWritingAnyOutput() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      session.create(index(0xF101, 1), null, null, new Data(7), false);
      SafeItemIteratorShareable iterator = session.list((short) 0);
      session.create(index(0xF101, 2), null, null, new Data(8), false);
      byte[] output = global(sequence(12, 31));
      byte[] original = output.clone();
      assertStatus(0x6985, () ->
        iterator.nextData(null, output, (short) 0, output, (short) 11, (short) 1)
      );
      Assertions.assertArrayEquals(original, output);
    }
  }

  @Test
  public void metadataIsCopiedBeforeExternalDataCallbacksAndResultsAreIndependent() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      byte[] index = index(0xF101, 1);
      byte[] original = index.clone();
      byte[] key = global(new byte[] { 4 });
      byte[] alias = global(new byte[] { 5 });
      Data source = new Data(6);
      source.onLength = () -> {
        index[0] = 0;
        key[0] = 9;
        alias[0] = 9;
      };
      SafeItemShareable item = session.create(index, key, alias, source, false);
      Assertions.assertArrayEquals(original, item.getIndex());
      Assertions.assertArrayEquals(new byte[] { 4 }, item.getKey());
      Assertions.assertArrayEquals(new byte[] { 5 }, item.getAlias());
      item.getIndex()[0] = 0;
      item.getKey()[0] = 0;
      item.getAlias()[0] = 0;
      Assertions.assertArrayEquals(original, item.getIndex());
      Assertions.assertEquals(4, item.getKey()[0]);
      Assertions.assertEquals(5, item.getAlias()[0]);
      item.setAlias(null);
      Assertions.assertNull(item.getAlias());
    }
  }

  @Test
  public void failedCallbacksCannotPublishAndCannotReenterStorage() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      Data source = new Data(5);
      source.onLength = () -> assertStatus(0x6985, () -> session.list((short) 0));
      SafeItemShareable item = session.create(index(0xF101, 1), null, null, source, false);
      source.onLength = null;
      source.onRead = () -> ISOException.throwIt((short) 0x6A80);
      assertStatus(0x6A80, () -> item.setData(source, true));
      Assertions.assertFalse(item.isSecret());
      Assertions.assertArrayEquals(new byte[] { 5 }, read(item.getData()));

      source.onRead = () -> assertStatus(0x6982, () -> session.authenticate(global(new byte[32])));
      assertStatus(0x6982, () -> session.create(index(0xF101, 2), null, null, source, false));
      session.authenticate(global(fixture.client.token));
      Assertions.assertNull(session.get(index(0xF101, 2)));
      Assertions.assertEquals(1, session.list((short) 0).getCount());
    }
  }

  @Test
  public void removalAndReplacementInvalidateStoredHandlesAndIteration() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      SafeItemShareable old = session.create(index(0xF101, 1), null, null, new Data(1), false);
      SafeDataShareable data = old.getData();
      SafeItemIteratorShareable iterator = session.list((short) 0);
      old.remove();
      session.create(index(0xF101, 1), null, null, new Data(2), false);
      assertStatus(0x6985, old::getIndex);
      assertStatus(0x6985, () -> old.setData(new Data(3)));
      assertStatus(0x6985, data::getLength);
      assertStatus(0x6985, () -> data.read((short) 0, global(new byte[1]), (short) 0, (short) 1));
      assertStatus(0x6985, iterator::next);
      Assertions.assertArrayEquals(new byte[] { 2 }, read(session.get(index(0xF101, 1)).getData()));
    }
  }

  @Test
  public void unrelatedDirectoryChangesPreserveItemAndDataHandles() {
    try (Fixture fixture = new Fixture()) {
      fixture.card.create(index(0xF102, 1), null, null, new byte[] { 17 }, false);
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      SafeItemShareable item = session.get(index(0xF102, 1));
      SafeDataShareable data = item.getData();
      SafeItemShareable other = session.create(index(0xF101, 2), null, null, new Data(2), false);
      Assertions.assertArrayEquals(index(0xF102, 1), item.getIndex());
      Assertions.assertArrayEquals(new byte[] { 17 }, read(data));
      other.remove();
      Assertions.assertArrayEquals(new byte[] { 17 }, read(item.getData()));
      Assertions.assertArrayEquals(new byte[] { 17 }, read(data));
      session.create(index(0xF101, 3), null, null, new Data(3), false);
      session.removeAll((short) 0xF101);
      Assertions.assertArrayEquals(index(0xF102, 1), item.getIndex());
      Assertions.assertArrayEquals(new byte[] { 17 }, read(data));
    }
  }

  @Test
  public void dataReplacementInvalidatesReadersWithoutADirectoryChange() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      SafeItemShareable item = session.create(index(0xF101, 1), null, null, new Data(1), false);
      SafeDataShareable prior = item.getData();
      item.setAlias(global(new byte[] { 3 }));
      Assertions.assertArrayEquals(new byte[] { 1 }, read(prior));
      item.setData(new Data(2));
      assertStatus(0x6985, prior::getLength);
      assertStatus(0x6985, () -> prior.read((short) 0, global(new byte[1]), (short) 0, (short) 1));
      Assertions.assertArrayEquals(new byte[] { 2 }, read(item.getData()));
    }
  }

  @Test
  public void resetRevocationAndWholeGrantReplacementInvalidateOldSessions() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid initial = fixture.connect(true);
      fixture.card.reset();
      fixture.card.simulator.selectApplet(CLIENT_AID);
      assertStatus(0x6982, () -> initial.authenticate(global(fixture.client.token)));
      Monoid afterReset = fixture.connect(true);
      SafeItemShareable replacedGrantItem = afterReset.create(
        index(0xF101, 1),
        null,
        null,
        new Data(1),
        false
      );
      SafeDataShareable replacedGrantData = replacedGrantItem.getData();
      fixture.grant(null);
      fixture.card.simulator.selectApplet(CLIENT_AID);
      assertStatus(0x6982, replacedGrantItem::getIndex);
      assertStatus(0x6982, () ->
        replacedGrantData.read((short) 0, global(new byte[1]), (short) 0, (short) 1)
      );
      assertStatus(0x6982, () -> afterReset.authenticate(global(fixture.client.token)));
      Monoid replacement = fixture.connect(true);
      SafeItemShareable revokedItem = replacement.get(index(0xF101, 1));
      SafeDataShareable revokedData = revokedItem.getData();
      fixture.manage(0x52, fields("aid", AppletTest.aidBytes(CLIENT_AID)));
      fixture.card.simulator.selectApplet(CLIENT_AID);
      assertStatus(0x6982, () -> replacement.list((short) 0));
      assertStatus(0x6982, revokedItem::getIndex);
      assertStatus(0x6982, () ->
        revokedData.read((short) 0, global(new byte[1]), (short) 0, (short) 1)
      );
      Assertions.assertNull(JCSystem.getAppletShareableInterfaceObject(MONOID_AID, (byte) 0));
      fixture.grant(null);
      Monoid restored = fixture.connect(true);
      fixture.card.simulator.selectApplet(MONOID_AID);
      fixture.card.success(0xFF, fields());
      fixture.card.simulator.selectApplet(CLIENT_AID);
      assertStatus(0x6982, () -> restored.authenticate(global(fixture.client.token)));
    }
  }

  @Test
  public void derivedPublicKeysAndRawSignaturesMatchIndependentHKDFAndECDSA() throws Exception {
    try (Fixture fixture = new Fixture()) {
      byte[] seed = sequence(64, 41);
      byte[] domain = new byte[] { 0, 7, (byte) 0xFF };
      byte[] context = sequence(79, 51);
      byte[] seedIndex = fixture.card.create("seed", null, null, seed, true);
      fixture.grant(fields("index", seedIndex, "domain", domain));
      fixture.card.reset();
      Monoid session = fixture.connect(true);
      byte[] actual = global(new byte[69]);
      byte[] digest = sequence(32, 61);
      byte[] signature = global(new byte[68]);
      byte[] expected = referencePublicKey(seed, domain, context);

      for (int pass = 0; pass < 2; pass++) {
        Assertions.assertEquals(
          65,
          session.getMonoid001PublicKey(global(context), actual, (short) 2)
        );
        Assertions.assertArrayEquals(expected, Arrays.copyOfRange(actual, 2, 67));
        Assertions.assertEquals(
          64,
          session.signMonoid001ECDSADigest(global(context), global(digest), signature, (short) 2)
        );
        assertSignature(expected, digest, Arrays.copyOfRange(signature, 2, 66));
      }

      fixture.card.simulator.selectApplet(MONOID_AID);
      fixture.card.authenticate(false);
      byte[] compressed = MonoidAppletGrantTest.success(
        fixture.card,
        0x40,
        fields(
          "index",
          seedIndex,
          "type",
          "seed",
          "derivation",
          fields("type", "monoid-001", "context", framed(domain, context))
        )
      ).bytes("publicKey");
      Assertions.assertArrayEquals(
        SECNamedCurves.getByName("secp256r1").getCurve().decodePoint(expected).getEncoded(true),
        compressed
      );
      fixture.card.simulator.selectApplet(CLIENT_AID);
      assertStatus(0x6982, () -> session.get(global(seedIndex)));
    }
  }

  @Test
  public void repeatedDerivationTracksMutableContextBytesAndIndependentSessions() throws Exception {
    try (Fixture fixture = new Fixture()) {
      byte[] seed = sequence(64, 21);
      byte[] domain = sequence(3, 41);
      byte[] seedIndex = fixture.card.create("seed", null, null, seed, true);
      fixture.grant(fields("index", seedIndex, "domain", domain));
      Monoid session = fixture.connect(true);
      byte[] context = global(sequence(79, 61));
      byte[] originalContext = context.clone();
      byte[] output = global(new byte[65]);
      byte[] digest = global(sequence(32, 81));
      byte[] signature = global(new byte[64]);
      session.getMonoid001PublicKey(context, output, (short) 0);
      Assertions.assertArrayEquals(referencePublicKey(seed, domain, originalContext), output);
      byte[] frame = privateFrame(session);
      Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(frame));
      Assertions.assertArrayEquals(framed(domain, originalContext), frame);

      context[0] ^= 1;
      context[context.length - 1] ^= 1;
      session.signMonoid001ECDSADigest(context, digest, signature, (short) 0);
      assertSignature(referencePublicKey(seed, domain, context), digest, signature);
      session.getMonoid001PublicKey(context, output, (short) 0);
      Assertions.assertArrayEquals(referencePublicKey(seed, domain, context), output);
      Assertions.assertSame(frame, privateFrame(session));
      Assertions.assertArrayEquals(framed(domain, context), frame);

      // Returning to an older context must hit an unchanged derivation-cache snapshot.
      session.getMonoid001PublicKey(global(originalContext), output, (short) 0);
      Assertions.assertSame(frame, privateFrame(session));
      Assertions.assertArrayEquals(referencePublicKey(seed, domain, originalContext), output);

      Monoid other = fixture.connect(true);
      other.getMonoid001PublicKey(global(originalContext), output, (short) 0);
      Assertions.assertArrayEquals(referencePublicKey(seed, domain, originalContext), output);
      Assertions.assertNotSame(frame, privateFrame(other));
      session.signMonoid001ECDSADigest(context, digest, signature, (short) 0);
      assertSignature(referencePublicKey(seed, domain, context), digest, signature);
      Assertions.assertSame(frame, privateFrame(session));
      Assertions.assertArrayEquals(framed(domain, originalContext), privateFrame(other));

      for (byte[] next : new byte[][] { new byte[0], new byte[] { 1 }, originalContext }) {
        byte[] expected = referencePublicKey(seed, domain, next);
        session.getMonoid001PublicKey(global(next), output, (short) 0);
        Assertions.assertArrayEquals(expected, output);
        session.signMonoid001ECDSADigest(global(next), digest, signature, (short) 0);
        assertSignature(expected, digest, signature);
      }
      assertStatus(0x6A80, () -> session.getMonoid001PublicKey(null, output, (short) 0));
      assertStatus(0x6A80, () ->
        session.signMonoid001ECDSADigest(null, digest, signature, (short) 0)
      );
    }
  }

  @Test
  public void unrelatedItemChangesPreserveTheSessionsSeedAndDerivedResult() throws Exception {
    try (Fixture fixture = new Fixture()) {
      byte[] seed = sequence(64, 21);
      byte[] domain = new byte[] { 3 };
      byte[] seedIndex = fixture.card.create("seed", null, null, seed, true);
      fixture.grant(fields("index", seedIndex, "domain", domain));
      Monoid session = fixture.connectReusable(true);
      byte[] context = global(sequence(79, 41));
      byte[] output = global(new byte[65]);
      byte[] digest = global(sequence(32, 61));
      byte[] signature = global(new byte[64]);
      byte[] expected = referencePublicKey(seed, domain, context);
      session.getMonoid001PublicKey(context, output, (short) 0);
      Object seedItem = privateField(session, "seedItem");
      Object revision = privateField(session, "seedRevision");
      Object derived = privateField(session, "derivedKey");

      SafeItemShareable other = session.create(index(0xF101, 1), null, null, new Data(1), false);
      session.signMonoid001ECDSADigest(context, digest, signature, (short) 0);
      assertSignature(expected, digest, signature);
      Assertions.assertSame(seedItem, privateField(session, "seedItem"));
      Assertions.assertNotSame(revision, privateField(session, "seedRevision"));
      Assertions.assertSame(derived, privateField(session, "derivedKey"));

      other.remove();
      session.getMonoid001PublicKey(context, output, (short) 0);
      Assertions.assertArrayEquals(expected, output);
      Assertions.assertSame(seedItem, privateField(session, "seedItem"));
      Assertions.assertSame(derived, privateField(session, "derivedKey"));

      // Reacquiring the reusable session still clears authorization before using the cache.
      Monoid reacquired = fixture.connectReusable(false);
      assertStatus(0x6982, () -> reacquired.getMonoid001PublicKey(context, output, (short) 0));
      reacquired.authenticate(global(fixture.client.token));
      reacquired.signMonoid001ECDSADigest(context, digest, signature, (short) 0);
      assertSignature(expected, digest, signature);
      Assertions.assertSame(derived, privateField(reacquired, "derivedKey"));
    }
  }

  @Test
  public void derivationFrameUsesPersistentStorageAndReusesPrivateFrames() throws Exception {
    try (Fixture fixture = new Fixture()) {
      byte[] seed = sequence(64, 21);
      byte[] domain = new byte[] { 1 };
      byte[] seedIndex = fixture.card.create("seed", null, null, seed, true);
      fixture.grant(fields("index", seedIndex, "domain", domain));
      Monoid session = fixture.connectReusable(true);
      byte[] output = global(new byte[65]);
      int prefixLength = framed(domain, new byte[0]).length;
      byte[] context = global(sequence(256 - prefixLength, 51));
      session.getMonoid001PublicKey(context, output, (short) 0);
      byte[] frame = privateFrame(session);
      Assertions.assertEquals(256, frame.length);
      Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(frame));
      Assertions.assertArrayEquals(referencePublicKey(seed, domain, context), output);
      context[0] ^= 1;
      session.getMonoid001PublicKey(context, output, (short) 0);
      Assertions.assertSame(frame, privateFrame(session));
      Assertions.assertArrayEquals(referencePublicKey(seed, domain, context), output);

      byte[] longer = global(sequence(257 - prefixLength, 71));
      session.getMonoid001PublicKey(longer, output, (short) 0);
      byte[] persistent = privateFrame(session);
      Assertions.assertEquals(257, persistent.length);
      Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(persistent));
      Assertions.assertNotSame(frame, persistent);
      Assertions.assertArrayEquals(referencePublicKey(seed, domain, longer), output);
      longer[longer.length - 1] ^= 1;
      session.getMonoid001PublicKey(longer, output, (short) 0);
      Assertions.assertSame(persistent, privateFrame(session));
      Assertions.assertArrayEquals(referencePublicKey(seed, domain, longer), output);

      byte[] savedFrame = frame.clone();
      fixture.card.reset();
      fixture.card.simulator.selectApplet(CLIENT_AID);
      Assertions.assertArrayEquals(savedFrame, frame);
      assertStatus(0x6982, () -> session.getMonoid001PublicKey(longer, output, (short) 0));
      Monoid replacement = fixture.connectReusable(true);
      replacement.getMonoid001PublicKey(context, output, (short) 0);
      Assertions.assertNotSame(frame, privateFrame(replacement));
      Assertions.assertArrayEquals(referencePublicKey(seed, domain, context), output);
    }
  }

  @Test
  public void repeatedDerivationStillRequiresAuthenticationAndTheCurrentGrant() throws Exception {
    try (Fixture fixture = new Fixture()) {
      byte[] seed = sequence(64, 11);
      byte[] domain = new byte[] { 1 };
      byte[] seedIndex = fixture.card.create("seed", null, null, seed, true);
      fixture.grant(fields("index", seedIndex, "domain", domain));
      Monoid session = fixture.connect(true);
      byte[] context = global(new byte[] { 2 });
      byte[] output = global(new byte[65]);
      byte[] digest = global(sequence(32, 31));
      byte[] signature = global(new byte[64]);
      session.getMonoid001PublicKey(context, output, (short) 0);
      assertStatus(0x6982, () -> session.authenticate(global(new byte[32])));
      assertStatus(0x6982, () -> session.getMonoid001PublicKey(context, output, (short) 0));
      assertStatus(0x6982, () ->
        session.signMonoid001ECDSADigest(context, digest, signature, (short) 0)
      );
      session.authenticate(global(fixture.client.token));
      session.signMonoid001ECDSADigest(context, digest, signature, (short) 0);
      assertSignature(referencePublicKey(seed, domain, context), digest, signature);

      fixture.manage(0x52, fields("aid", AppletTest.aidBytes(CLIENT_AID)));
      fixture.card.simulator.selectApplet(CLIENT_AID);
      assertStatus(0x6982, () -> session.getMonoid001PublicKey(context, output, (short) 0));
      assertStatus(0x6982, () ->
        session.signMonoid001ECDSADigest(context, digest, signature, (short) 0)
      );
      byte[] nextDomain = new byte[] { 3 };
      fixture.grant(fields("index", seedIndex, "domain", nextDomain));
      Monoid replacement = fixture.connect(true);
      assertStatus(0x6982, () -> session.getMonoid001PublicKey(context, output, (short) 0));
      replacement.getMonoid001PublicKey(context, output, (short) 0);
      Assertions.assertArrayEquals(referencePublicKey(seed, nextDomain, context), output);
      replacement.signMonoid001ECDSADigest(context, digest, signature, (short) 0);
      assertSignature(referencePublicKey(seed, nextDomain, context), digest, signature);
    }
  }

  @Test
  public void derivationUsesCurrentSeedAndRejectsUnavailableSourcesOrMissingPermission()
    throws Exception {
    try (Fixture fixture = new Fixture()) {
      byte[] seedIndex = fixture.card.create("seed", null, null, sequence(64, 1), true);
      byte[] domain = new byte[] { 1 };
      fixture.grant(fields("index", seedIndex, "domain", domain));
      Monoid session = fixture.connect(true);
      byte[] output = global(new byte[65]);
      byte[] context = global(new byte[] { 2 });
      byte[] digest = global(sequence(32, 5));
      byte[] signature = global(new byte[64]);
      session.getMonoid001PublicKey(context, output, (short) 0);
      byte[] prior = output.clone();
      fixture.manage(0x33, fields("index", seedIndex, "data", sequence(64, 2)));
      fixture.card.simulator.selectApplet(CLIENT_AID);
      session.signMonoid001ECDSADigest(context, digest, signature, (short) 0);
      assertSignature(referencePublicKey(sequence(64, 2), domain, context), digest, signature);
      session.getMonoid001PublicKey(context, output, (short) 0);
      Assertions.assertFalse(Arrays.equals(prior, output));
      Assertions.assertArrayEquals(referencePublicKey(sequence(64, 2), domain, context), output);
      fixture.manage(0x33, fields("index", seedIndex, "data", new byte[32]));
      fixture.card.simulator.selectApplet(CLIENT_AID);
      assertStatus(0x6985, () -> session.getMonoid001PublicKey(context, output, (short) 0));
      assertStatus(0x6985, () ->
        session.signMonoid001ECDSADigest(context, digest, signature, (short) 0)
      );
      fixture.manage(0x35, fields("index", seedIndex));
      fixture.card.simulator.selectApplet(CLIENT_AID);
      assertStatus(0x6985, () -> session.getMonoid001PublicKey(context, output, (short) 0));
      assertStatus(0x6985, () ->
        session.signMonoid001ECDSADigest(context, digest, signature, (short) 0)
      );
      byte[] restored = sequence(64, 9);
      // Known seed creation binds the index to its original digest; updates may replace data.
      fixture.manage(0x34, fields("index", seedIndex, "data", sequence(64, 1), "secret", true));
      fixture.manage(0x33, fields("index", seedIndex, "data", restored));
      fixture.card.simulator.selectApplet(CLIENT_AID);
      session.getMonoid001PublicKey(context, output, (short) 0);
      Assertions.assertArrayEquals(referencePublicKey(restored, domain, context), output);
      session.signMonoid001ECDSADigest(context, digest, signature, (short) 0);
      assertSignature(referencePublicKey(restored, domain, context), digest, signature);
      fixture.grant(null);
      Monoid withoutSeed = fixture.connect(true);
      assertStatus(0x6982, () -> withoutSeed.getMonoid001PublicKey(context, output, (short) 0));
      assertStatus(0x6982, () ->
        withoutSeed.signMonoid001ECDSADigest(context, digest, signature, (short) 0)
      );
    }
  }

  @Test
  public void boundedCredentialReplacementParticipatesInTheClientsTransaction() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      SafeItemShareable prior = session.create(index(0xF101, 1), null, null, new Data(1), false);
      JCSystem.beginTransaction();
      try {
        SafeItemShareable replacement = session.create(
          index(0xF101, 2),
          null,
          null,
          new Data(2),
          false
        );
        Assertions.assertEquals(1, JCSystem.getTransactionDepth());
        replacement.setData(new Data(3));
        Assertions.assertEquals(1, JCSystem.getTransactionDepth());
        prior.remove();
        Assertions.assertEquals(1, JCSystem.getTransactionDepth());
        JCSystem.commitTransaction();
      } finally {
        if (JCSystem.getTransactionDepth() != 0) {
          JCSystem.abortTransaction();
        }
      }
      Assertions.assertNull(session.get(index(0xF101, 1)));
      Assertions.assertArrayEquals(new byte[] { 3 }, read(session.get(index(0xF101, 2)).getData()));
    }
  }

  @Test
  public void bulkRemovalRequiresExactWritablePermissionEvenForAnEmptyType() {
    try (Fixture fixture = new Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(false);
      assertStatus(0x6982, () -> session.removeAll((short) 0xF101));
      session.authenticate(global(fixture.client.token));
      assertStatus(0x6982, () -> session.removeAll((short) 0xF102));
      assertStatus(0x6982, () -> session.removeAll((short) 0xF100));
      assertStatus(0x6982, () -> session.removeAll((short) 0));
      session.removeAll((short) 0xF101);
      fixture.manage(0x51, fields("aid", AppletTest.aidBytes(CLIENT_AID)));
      Monoid emptyGrant = fixture.connect(true);
      assertStatus(0x6982, () -> emptyGrant.removeAll((short) 0xF101));
    }
  }

  @Test
  public void bulkRemovalPreservesOtherTypesAndInvalidatesRemovedItemsAndIterators() {
    try (Fixture fixture = new Fixture()) {
      fixture.card.create(index(0xF102, 1), null, null, new byte[] { 17 }, false);
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      SafeItemShareable first = null;
      for (int index = 1; index <= 19; index++) {
        SafeItemShareable item = session.create(
          index(0xF101, index),
          null,
          null,
          new Data(index),
          false
        );
        if (first == null) {
          first = item;
        }
      }
      SafeDataShareable removedData = first.getData();
      SafeItemShareable preserved = session.get(index(0xF102, 1));
      SafeItemIteratorShareable iterator = session.list((short) 0);
      session.removeAll((short) 0xF101);
      Assertions.assertEquals(1, session.list((short) 0).getCount());
      Assertions.assertArrayEquals(new byte[] { 17 }, read(preserved.getData()));
      assertStatus(0x6985, first::getIndex);
      assertStatus(0x6985, removedData::getLength);
      assertStatus(0x6985, iterator::next);
      session.removeAll((short) 0xF101);
      Assertions.assertNotNull(session.create(index(0xF101, 1), null, null, new Data(1), false));
    }
  }

  @Test
  public void bulkRemovalTreatsAZeroLowByteAsAnExactTypeAndJoinsAnOuterTransaction() {
    try (Fixture fixture = new Fixture()) {
      fixture.card.create(index(0xF100, 1), null, null, new byte[] { 1 }, false);
      fixture.card.create(index(0xF101, 2), null, null, new byte[] { 2 }, false);
      fixture.manage(
        0x51,
        fields(
          "aid",
          AppletTest.aidBytes(CLIENT_AID),
          "types",
          Arrays.asList(Arrays.asList((short) 0xF100, true), Arrays.asList((short) 0xF101, true))
        )
      );
      Monoid session = fixture.connect(true);
      JCSystem.beginTransaction();
      try {
        session.removeAll((short) 0xF100);
        Assertions.assertEquals(1, JCSystem.getTransactionDepth());
        Assertions.assertNull(session.get(index(0xF100, 1)));
        Assertions.assertArrayEquals(
          new byte[] { 2 },
          read(session.get(index(0xF101, 2)).getData())
        );
        JCSystem.commitTransaction();
      } finally {
        if (JCSystem.getTransactionDepth() != 0) {
          JCSystem.abortTransaction();
        }
      }
      Assertions.assertEquals(1, session.list((short) 0).getCount());
    }
  }

  private static byte[] referencePublicKey(byte[] seed, byte[] domain, byte[] context)
    throws Exception {
    Mac hmac = Mac.getInstance("HmacSHA512");
    byte[] label = "Monoid-001".getBytes(StandardCharsets.US_ASCII);
    hmac.init(new SecretKeySpec(label, "HmacSHA512"));
    byte[] master = hmac.doFinal(seed);
    hmac.init(new SecretKeySpec(master, "HmacSHA512"));
    X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
    for (int counter = 0; counter < 256; counter++) {
      hmac.update(label);
      hmac.update((byte) 0);
      hmac.update(framed(domain, context));
      hmac.update((byte) counter);
      hmac.update((byte) 1);
      BigInteger scalar = new BigInteger(1, Arrays.copyOf(hmac.doFinal(), 32));
      if (scalar.signum() > 0 && scalar.compareTo(curve.getN()) < 0) {
        return curve.getG().multiply(scalar).normalize().getEncoded(false);
      }
    }
    throw new AssertionError("HKDF rejection limit");
  }

  private static byte[] privateFrame(Monoid session) throws Exception {
    return privateBytes(session, "framedContext");
  }

  private static byte[] privateBytes(Monoid session, String name) throws Exception {
    return (byte[]) privateField(session, name);
  }

  private static Object privateField(Object session, String name) throws Exception {
    Object target = session;
    if (java.lang.reflect.Proxy.isProxyClass(session.getClass())) {
      Object handler = java.lang.reflect.Proxy.getInvocationHandler(session);
      for (java.lang.reflect.Field captured : handler.getClass().getDeclaredFields()) {
        captured.setAccessible(true);
        Object value = captured.get(handler);
        if (value instanceof javacard.framework.Shareable) {
          target = value;
          break;
        }
      }
    }
    java.lang.reflect.Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(target);
  }

  private static byte[] framed(byte[] domain, byte[] context) {
    byte[] label = "monoid applet: ".getBytes(StandardCharsets.US_ASCII);
    byte[] result = Arrays.copyOf(label, label.length + 2 + domain.length + context.length);
    result[label.length] = (byte) (domain.length >>> 8);
    result[label.length + 1] = (byte) domain.length;
    System.arraycopy(domain, 0, result, label.length + 2, domain.length);
    System.arraycopy(context, 0, result, label.length + 2 + domain.length, context.length);
    return result;
  }

  private static void assertSignature(byte[] publicKey, byte[] digest, byte[] signature) {
    X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
    ECDomainParameters parameters = new ECDomainParameters(
      curve.getCurve(),
      curve.getG(),
      curve.getN(),
      curve.getH()
    );
    ECDSASigner verifier = new ECDSASigner();
    verifier.init(
      false,
      new ECPublicKeyParameters(curve.getCurve().decodePoint(publicKey), parameters)
    );
    Assertions.assertTrue(
      verifier.verifySignature(
        digest,
        new BigInteger(1, Arrays.copyOfRange(signature, 0, 32)),
        new BigInteger(1, Arrays.copyOfRange(signature, 32, 64))
      )
    );
  }

  private static byte[] index(int type, int id) {
    byte[] index = new byte[10];
    index[0] = (byte) (type >>> 8);
    index[1] = (byte) type;
    index[9] = (byte) id;
    return global(index);
  }

  private static byte[] global(byte[] data) {
    return Utils.duplicateAsGlobal(data);
  }

  private static byte[] sequence(int length, int start) {
    byte[] result = new byte[length];
    for (int index = 0; index < length; index++) {
      result[index] = (byte) (start + index);
    }
    return result;
  }

  private static byte[] read(SafeDataShareable source) {
    byte[] data = global(new byte[source.getLength()]);
    source.read((short) 0, data, (short) 0, (short) data.length);
    return data;
  }

  private static void assertStatus(int status, Runnable action) {
    Assertions.assertEquals(
      status,
      Assertions.assertThrows(ISOException.class, action::run).getReason() & 0xFFFF
    );
  }

  static final class Fixture implements AutoCloseable {

    final Card card = new Card(true);
    final AppletGrantClient client;

    Fixture() {
      card.simulator.installApplet(CLIENT_AID, AppletGrantClient.class);
      client = AppletGrantClient.installed;
    }

    void grant(Map<String, Object> seed) {
      Map<String, Object> request = fields(
        "aid",
        AppletTest.aidBytes(CLIENT_AID),
        "types",
        Arrays.asList(Arrays.asList((short) 0xF101, true), Arrays.asList((short) 0xF102, false))
      );
      if (seed != null) {
        request.put("seed", seed);
      }
      manage(0x51, request);
    }

    void manage(int instruction, Map<String, Object> request) {
      card.simulator.selectApplet(MONOID_AID);
      card.authenticate(true);
      MonoidAppletGrantTest.success(card, instruction, request);
    }

    Monoid connect(boolean authenticate) {
      return connect(authenticate, (byte) 0);
    }

    Monoid connectReusable(boolean authenticate) {
      return connect(authenticate, (byte) 1);
    }

    private Monoid connect(boolean authenticate, byte parameter) {
      card.simulator.selectApplet(CLIENT_AID);
      Monoid session = (Monoid) JCSystem.getAppletShareableInterfaceObject(MONOID_AID, parameter);
      Assertions.assertNotNull(session);
      if (authenticate) {
        session.authenticate(global(client.token));
      }
      return session;
    }

    @Override
    public void close() {
      card.simulator.deleteApplet(CLIENT_AID);
      card.close();
    }
  }

  public static class Data implements SafeDataShareable {

    final byte[] data;
    Runnable onLength;
    Runnable onRead;

    Data(int value) {
      data = new byte[] { (byte) value };
    }

    @Override
    public short getLength() {
      if (onLength != null) {
        onLength.run();
      }
      return (short) data.length;
    }

    @Override
    public void read(short offset, byte[] buffer, short bufferOffset, short length) {
      if (onRead != null) {
        onRead.run();
      }
      Util.arrayCopyNonAtomic(data, offset, buffer, bufferOffset, length);
    }
  }
}
