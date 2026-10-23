package tests;

import java.util.Arrays;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import monoid.Monoid;
import monoid.SafeDataShareable;
import monoid.SafeItemIteratorShareable;
import monoid.SafeItemShareable;
import monoid.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class MonoidCreateDataTest {

  @Test
  public void overlappingSlicesBecomeOwnedDataAndPublishOneDirectoryRevision() {
    try (MonoidSessionTest.Fixture fixture = new MonoidSessionTest.Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      byte[] input = global(sequence(260));
      byte[] index = index(0xF101, 1);
      System.arraycopy(index, 0, input, 5, 10);
      byte[] alias = global(new byte[] { 1, 2 });
      byte[] expectedData = Arrays.copyOfRange(input, 20, 247);
      byte[] expectedKey = Arrays.copyOfRange(input, 45, 77);
      byte[] original = input.clone();
      SafeItemIteratorShareable before = session.list((short) 0);

      Assertions.assertTrue(
        session.createData(
          input,
          (short) 5,
          input,
          (short) 45,
          (short) 32,
          alias,
          input,
          (short) 20,
          (short) 227,
          false
        )
      );
      Assertions.assertArrayEquals(original, input);
      Assertions.assertEquals(0, JCSystem.getTransactionDepth());
      assertStatus(0x6985, before::next);
      Arrays.fill(input, (byte) 0);
      Arrays.fill(alias, (byte) 0);

      SafeItemShareable stored = session.get(index);
      Assertions.assertArrayEquals(index, stored.getIndex());
      Assertions.assertArrayEquals(expectedKey, stored.getKey());
      Assertions.assertArrayEquals(new byte[] { 1, 2 }, stored.getAlias());
      Assertions.assertArrayEquals(expectedData, read(stored.getData()));
      SafeItemIteratorShareable unchanged = session.list((short) 0);
      Assertions.assertFalse(create(session, index, global(new byte[] { 9 }), false));
      Assertions.assertNotNull(unchanged.next());
      Assertions.assertNull(unchanged.next());
      Assertions.assertArrayEquals(expectedData, read(stored.getData()));
    }
  }

  @Test
  public void invalidRangesDoNotCreateItemsOrChangeInputs() {
    try (MonoidSessionTest.Fixture fixture = new MonoidSessionTest.Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      byte[] index = index(0xF101, 1);
      byte[] data = global(sequence(32));
      byte[] original = data.clone();
      for (short offset : new short[] { -1, 1, 32767 }) {
        assertStatus(0x6A80, () ->
          session.createData(
            index,
            offset,
            null,
            (short) 0,
            (short) 0,
            null,
            data,
            (short) 0,
            (short) 32,
            false
          )
        );
      }
      for (short offset : new short[] { -1, 33, 32767 }) {
        assertStatus(0x6A80, () ->
          session.createData(
            index,
            (short) 0,
            data,
            offset,
            (short) 1,
            null,
            data,
            (short) 0,
            (short) 32,
            false
          )
        );
        assertStatus(0x6A80, () ->
          session.createData(
            index,
            (short) 0,
            null,
            (short) 0,
            (short) 0,
            null,
            data,
            offset,
            (short) 1,
            false
          )
        );
      }
      for (short length : new short[] { -1, 33, 32767 }) {
        assertStatus(0x6A80, () ->
          session.createData(
            index,
            (short) 0,
            data,
            (short) 0,
            length,
            null,
            data,
            (short) 0,
            (short) 32,
            false
          )
        );
        assertStatus(0x6A80, () ->
          session.createData(
            index,
            (short) 0,
            null,
            (short) 0,
            (short) 0,
            null,
            data,
            (short) 0,
            length,
            false
          )
        );
      }
      assertStatus(0x6A80, () ->
        session.createData(
          null,
          (short) 0,
          null,
          (short) 0,
          (short) 0,
          null,
          data,
          (short) 0,
          (short) 32,
          false
        )
      );
      assertStatus(0x6A80, () ->
        session.createData(
          index,
          (short) 0,
          null,
          (short) 1,
          (short) 0,
          null,
          data,
          (short) 0,
          (short) 32,
          false
        )
      );
      assertStatus(0x6A80, () ->
        session.createData(
          index,
          (short) 0,
          null,
          (short) 0,
          (short) 1,
          null,
          data,
          (short) 0,
          (short) 32,
          false
        )
      );
      assertStatus(0x6A80, () -> create(session, index, null, false));
      Assertions.assertEquals(0, session.list((short) 0).getCount());
      Assertions.assertArrayEquals(original, data);
      Assertions.assertEquals(0, JCSystem.getTransactionDepth());
    }
  }

  @Test
  public void creationRequiresFreshWritableAuthorizationAndPreservesSecretProtection() {
    try (MonoidSessionTest.Fixture fixture = new MonoidSessionTest.Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(false);
      byte[] data = global(new byte[] { 1 });
      assertStatus(0x6982, () -> create(session, index(0xF101, 1), data, false));
      session.authenticate(global(fixture.client.token));
      assertStatus(0x6982, () -> create(session, index(0xF102, 1), data, false));
      assertStatus(0x6982, () -> create(session, index(0xF103, 1), data, false));
      Assertions.assertEquals(0, session.list((short) 0).getCount());
      fixture.grant(null);
      Monoid current = fixture.connect(true);
      assertStatus(0x6982, () -> create(session, index(0xF101, 1), data, false));
      Assertions.assertTrue(create(current, index(0xF101, 1), data, true));
      SafeItemShareable item = current.get(index(0xF101, 1));
      Assertions.assertTrue(item.isSecret());
      assertStatus(0x6982, item::getData);
    }
  }

  @Test
  public void nullAndEmptyKeysRemainDistinctAndZeroLengthDataIsSupported() {
    try (MonoidSessionTest.Fixture fixture = new MonoidSessionTest.Fixture()) {
      fixture.grant(null);
      Monoid session = fixture.connect(true);
      byte[] empty = global(new byte[0]);
      Assertions.assertTrue(create(session, index(0xF101, 1), empty, false));
      Assertions.assertTrue(
        session.createData(
          index(0xF101, 2),
          (short) 0,
          empty,
          (short) 0,
          (short) 0,
          empty,
          empty,
          (short) 0,
          (short) 0,
          false
        )
      );
      Assertions.assertNull(session.get(index(0xF101, 1)).getKey());
      SafeItemShareable second = session.get(index(0xF101, 2));
      Assertions.assertArrayEquals(new byte[0], second.getKey());
      Assertions.assertArrayEquals(new byte[0], second.getAlias());
      Assertions.assertArrayEquals(new byte[0], read(second.getData()));
    }
  }

  private static boolean create(Monoid session, byte[] index, byte[] data, boolean secret) {
    return session.createData(
      index,
      (short) 0,
      null,
      (short) 0,
      (short) 0,
      null,
      data,
      (short) 0,
      data == null ? 0 : (short) data.length,
      secret
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

  private static byte[] sequence(int length) {
    byte[] result = new byte[length];
    for (int i = 0; i < length; i++) {
      result[i] = (byte) (i * 17 + 5);
    }
    return result;
  }

  private static byte[] read(SafeDataShareable source) {
    byte[] result = global(new byte[source.getLength()]);
    source.read((short) 0, result, (short) 0, (short) result.length);
    return result;
  }

  private static void assertStatus(int status, Runnable action) {
    Assertions.assertEquals(
      status,
      Assertions.assertThrows(ISOException.class, action::run).getReason() & 0xffff
    );
  }
}
