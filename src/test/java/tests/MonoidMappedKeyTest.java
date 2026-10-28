package tests;

import static tests.MonoidClientFixture.*;
import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.assertISOError;
import static tests.MonoidItemTransferTest.fields;
import static tests.MonoidItemTransferTest.sequence;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import monoid.Monoid;
import monoid.SafeDataShareable;
import monoid.SafeException;
import monoid.SafeItemShareable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

public class MonoidMappedKeyTest {

  private static final short TYPE = (short) 0xF201;
  private static final byte[] CONFIGURATION = { 1, 2, 6, 0, 30 };

  @Test
  public void createsOneSecretItemWithTheSameDigestSuffixAsHmac() throws Exception {
    try (Card card = new Card(true)) {
      for (int length : new int[] { 1, 20, 32, 64, 131, 255 }) {
        byte[] secret = sequence(length);
        byte[] index = card.create(TYPE, CONFIGURATION, "account", secret, false);
        byte[] hmac = card.create("hmac", null, null, secret, true);

        Assertions.assertArrayEquals(digestIndex(secret), index);
        Assertions.assertArrayEquals(
          Arrays.copyOfRange(hmac, 2, 10),
          Arrays.copyOfRange(index, 2, 10)
        );
        assertSecret(card, index);
        Assertions.assertArrayEquals(
          CONFIGURATION,
          card.success(0x31, fields("index", index)).bytes("metadata")
        );
        assertError(card.transmit(0x34, fields("type", TYPE, "data", secret)), "EXISTS");

        card.success(0x35, fields("index", index));
        Assertions.assertArrayEquals(
          index,
          card.create(index, CONFIGURATION, "restored", secret, null)
        );
        assertSecret(card, index);
      }

      byte[] omitted = card.create(TYPE, CONFIGURATION, null, new byte[] { 99 }, null);
      assertSecret(card, omitted);
      Assertions.assertEquals(
        7,
        card.success(0x30, fields("type", TYPE)).reader().requireKey(ascii("items")).array()
      );
    }
  }

  @Test
  public void rejectsInvalidSecretsAndSuppliedDigestsWithoutChangingUnmappedTypes()
    throws Exception {
    try (Card card = new Card(true)) {
      for (int length : new int[] { 0, 256 }) {
        byte[] secret = sequence(length);
        assertError(card.transmit(0x34, fields("type", TYPE, "data", secret)), "INVALID_PARAMETER");
        assertError(
          card.transmit(0x34, fields("index", digestIndex(secret), "data", secret)),
          "INVALID_PARAMETER"
        );
      }

      byte[] secret = sequence(32);
      byte[] incorrect = digestIndex(secret);
      incorrect[9] ^= 1;
      assertError(
        card.transmit(0x34, fields("index", incorrect, "data", secret)),
        "INVALID_PARAMETER"
      );
      Assertions.assertEquals(
        0,
        card.success(0x30, fields("type", TYPE)).reader().requireKey(ascii("items")).array()
      );

      byte[] custom = index(0xF202, 1);
      card.create(custom, null, null, secret, false);
      Assertions.assertArrayEquals(
        secret,
        card.success(0x32, fields("index", custom)).bytes("data")
      );
    }
  }

  @Test
  public void setCannotChangeTheDigestOrExposeTheSecret() {
    try (Card card = new Card(true)) {
      byte[] secret = sequence(32);
      byte[] index = card.create(TYPE, CONFIGURATION, "before", secret, false);

      card.success(0x33, fields("index", index, "data", secret, "secret", false, "alias", "after"));
      assertSecret(card, index);
      Assertions.assertArrayEquals(
        ascii("after"),
        card.success(0x31, fields("index", index)).reader().requireKey(ascii("alias")).text()
      );

      byte[] changed = secret.clone();
      changed[0] ^= 1;

      for (byte[] invalid : new byte[][] { changed, new byte[0], new byte[256] }) {
        assertError(
          card.transmit(0x33, fields("index", index, "data", invalid, "secret", false)),
          "INVALID_PARAMETER"
        );
        assertSecret(card, index);
      }

      assertISOError(card.transmit(0x33, fields("index", index, "secret", false)), 0x6985);
      card.success(0x33, fields("index", index, "data", secret));
      assertSecret(card, index);
    }
  }

  @Test
  public void encryptedTransferRestoresTheSingleAccountWithItsSecretAndMetadata() {
    try (Card card = new Card(true)) {
      byte[] secret = sequence(255);
      byte[] index = card.create(TYPE, CONFIGURATION, "account", secret, false);
      byte[] publicKey = card.publicKey();
      card.authenticate(true);
      Result exported = card.success(0x36, fields("index", index, "recipientPublicKey", publicKey));
      byte[] ciphertext = exported.bytes("data");
      Assertions.assertFalse(Arrays.equals(secret, ciphertext));
      Map<String, Object> imported = fields(
        "index",
        index,
        "metadata",
        exported.bytes("metadata"),
        "alias",
        "account",
        "senderPublicKey",
        publicKey,
        "data",
        ciphertext
      );

      card.success(0x35, fields("index", index));
      card.success(0x37, imported);
      assertError(card.transmit(0x37, imported), "EXISTS");
      assertSecret(card, index);
      Assertions.assertArrayEquals(
        CONFIGURATION,
        card.success(0x31, fields("index", index)).bytes("metadata")
      );
      Assertions.assertArrayEquals(
        ascii("account"),
        card.success(0x31, fields("index", index)).reader().requireKey(ascii("alias")).text()
      );
    }
  }

  @Test
  public void readOnlyTypeGrantUsesCurrentAccountsAndCannotReadOrWriteTheirSecrets()
    throws Exception {
    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      byte[] secret = sequence(32);
      byte[] index = fixture.card.create(TYPE, CONFIGURATION, "account", secret, false);
      byte[] hmac = fixture.card.create("hmac", null, null, secret, true);
      fixture.grant(CLIENT, "types", Arrays.asList(Arrays.asList(TYPE, false)));
      fixture.grant(OTHER, "keys", Arrays.asList(fields("index", hmac, "type", "hmac")));
      byte[] grant = fixture.card.success(0x50, fields()).data;
      Monoid reader = fixture.connect();
      SafeItemShareable item = reader.get(global(index));

      Assertions.assertTrue(item.isSecret());
      Assertions.assertArrayEquals(CONFIGURATION, item.getMetadata());
      Assertions.assertArrayEquals(ascii("account"), item.getAlias());
      assertStatus(0x6982, () -> item.getData());
      assertStatus(0x6982, () ->
        reader.getData(global(index), (short) 0, global(CONFIGURATION), (short) 0, (short) 5)
      );
      byte[] output = global(sequence(64));
      byte[] unchanged = output.clone();
      assertStatus(0x6982, () ->
        reader.readData(global(index), global(CONFIGURATION), output, (short) 0, (short) 64)
      );
      assertStatus(0x6982, () ->
        reader
          .list(TYPE)
          .nextData(
            global(CONFIGURATION),
            global(new byte[10]),
            (short) 0,
            output,
            (short) 0,
            (short) 64
          )
      );
      Assertions.assertArrayEquals(unchanged, output);
      assertStatus(0x6982, () -> item.setAlias(global(ascii("denied"))));
      assertStatus(0x6982, () -> item.remove());
      assertStatus(0x6982, () -> hmac(reader, hmac));
      assertHmac(secret, hmac(reader, index));

      Monoid other = fixture.connect(OTHER, (byte) 0, true);
      assertHmac(secret, hmac(other, hmac));
      assertStatus(0x6982, () -> hmac(other, index));

      fixture.select(MONOID);
      fixture.card.authenticate(false);
      fixture.card.success(0x35, fields("index", index));
      byte[] addedSecret = sequence(20);
      byte[] added = fixture.card.create(TYPE, CONFIGURATION, null, addedSecret, false);
      Assertions.assertArrayEquals(grant, fixture.card.success(0x50, fields()).data);
      fixture.select(CLIENT);
      assertStatus(0x6985, () -> hmac(reader, index));
      assertHmac(addedSecret, hmac(reader, added));

      fixture.select(MONOID);
      fixture.card.authenticate(false);
      fixture.grant(CLIENT, "types", Arrays.asList(Arrays.asList((short) 0xF200, false)));
      fixture.select(CLIENT);
      assertStatus(0x6982, () -> hmac(reader, added));
      Monoid category = fixture.connect();
      assertStatus(0x6982, () -> hmac(category, added));
    }
  }

  @Test
  public void writableClientsCreateValidatedSecretItemsThroughBothSioPaths() throws Exception {
    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      fixture.grant(CLIENT, "types", Arrays.asList(Arrays.asList(TYPE, true)));
      Monoid session = fixture.connect();
      byte[] secret = sequence(32);
      byte[] index = global(digestIndex(secret));
      byte[] configuration = global(CONFIGURATION);
      SafeDataShareable source = new SafeDataShareable() {
        @Override
        public short getLength() {
          return (short) secret.length;
        }

        @Override
        public void read(short offset, byte[] dest, short destOffset, short length) {
          System.arraycopy(secret, offset, dest, destOffset, length);
        }
      };

      SafeItemShareable item = session.create(index, configuration, null, source, false);
      Assertions.assertTrue(item.isSecret());
      item.setData(source, false);
      assertStatus(0x6982, () -> item.getData());
      assertHmac(secret, hmac(session, index));
      item.remove();

      byte[] data = global(secret);
      Assertions.assertTrue(
        session.createData(
          index,
          (short) 0,
          configuration,
          (short) 0,
          (short) 5,
          null,
          data,
          (short) 0,
          (short) data.length,
          false
        )
      );
      Assertions.assertFalse(
        session.createData(
          index,
          (short) 0,
          configuration,
          (short) 0,
          (short) 5,
          null,
          data,
          (short) 0,
          (short) data.length,
          false
        )
      );
      Assertions.assertTrue(session.get(index).isSecret());
      assertHmac(secret, hmac(session, index));
      session.removeAll(TYPE);
      index[9] ^= 1;

      Assertions.assertEquals(
        SafeException.REASON_INVALID_PARAMETER,
        Assertions.assertThrows(SafeException.class, () ->
          session.create(index, configuration, null, source, false)
        ).getReason()
      );
      Assertions.assertEquals(
        SafeException.REASON_INVALID_PARAMETER,
        Assertions.assertThrows(SafeException.class, () ->
          session.createData(
            index,
            (short) 0,
            configuration,
            (short) 0,
            (short) 5,
            null,
            data,
            (short) 0,
            (short) data.length,
            false
          )
        ).getReason()
      );
      Assertions.assertEquals(0, session.list(TYPE).getCount());
    }
  }

  private static void assertSecret(Card card, byte[] index) {
    Assertions.assertTrue(
      card.success(0x31, fields("index", index)).reader().requireKey(ascii("secret")).bool()
    );
    assertError(card.transmit(0x32, fields("index", index)), "ACCESS_DENIED");
  }

  private static byte[] digestIndex(byte[] secret) throws Exception {
    byte[] index = index(TYPE, 0);
    System.arraycopy(MessageDigest.getInstance("SHA-256").digest(secret), 0, index, 2, 8);
    return index;
  }

  private static byte[] hmac(Monoid session, byte[] index) {
    byte[] output = global(new byte[32]);
    Assertions.assertEquals(
      32,
      session.hmac(
        Monoid.HMAC_SHA256,
        global(index),
        (short) 0,
        global(new byte[0]),
        (short) 0,
        (short) 0,
        output,
        (short) 0
      )
    );
    return output;
  }

  private static void assertHmac(byte[] secret, byte[] actual) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(secret, "HmacSHA256"));
    Assertions.assertArrayEquals(mac.doFinal(), actual);
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }
}
