package tests;

import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.fields;
import static tests.MonoidItemTransferTest.sequence;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;
import monoid.Safe;
import monoidlib.CBORBufferReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

public class MonoidHMACKeyTest {

  @Test
  public void createsDigestIndexedKeysAndListsTheBuiltInCategory() throws Exception {
    int[] lengths = { 1, 20, 32, 64, 131, 255 };

    try (Card card = new Card(true)) {
      byte[][] indices = new byte[lengths.length][];

      for (int position = 0; position < lengths.length; position++) {
        byte[] data = sequence(lengths[position]);
        byte[] index = card.create("hmac", null, null, data, false);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);

        Assertions.assertEquals(5, index[0]);
        Assertions.assertEquals(lengths[position], index[1] & 0xFF);
        Assertions.assertArrayEquals(
          Arrays.copyOf(digest, Safe.INDEX_ID_LENGTH),
          Arrays.copyOfRange(index, Safe.INDEX_ID_OFFSET, Safe.INDEX_LENGTH)
        );
        Assertions.assertArrayEquals(
          data,
          card.success(0x32, fields("index", index)).bytes("data")
        );

        indices[position] = index;
      }

      for (Object selector : new Object[] { "hmac", Safe.TYPE_HMAC }) {
        CBORBufferReader reader = card.success(0x30, fields("type", selector)).reader();
        Assertions.assertEquals(lengths.length, reader.requireKey(ascii("items")).array());

        for (short position = 0; position < lengths.length; position++) {
          Assertions.assertTrue(reader.index(position));
          reader.map();
          Assertions.assertArrayEquals(ascii("hmac"), reader.requireKey(ascii("type")).text());
          Assertions.assertArrayEquals(
            indices[position],
            reader.requireKey(ascii("index")).bytes()
          );
        }
      }

      CBORBufferReader reader = card.success(0x30, fields("type", Safe.TYPE_HMAC | 32)).reader();
      Assertions.assertEquals(1, reader.requireKey(ascii("items")).array());
    }
  }

  @Test
  public void rejectsInvalidCreateLengthsAndMismatchedExplicitIndices() {
    try (Card card = new Card(true)) {
      for (int length : new int[] { 0, 256 }) {
        assertError(
          card.transmit(0x34, fields("type", "hmac", "data", new byte[length])),
          "INVALID_PARAMETER"
        );
      }

      assertError(
        card.transmit(0x34, fields("type", Safe.TYPE_HMAC | 32, "data", new byte[20])),
        "INVALID_PARAMETER"
      );

      byte[] data = sequence(32);
      byte[] index = card.create("hmac", null, null, data, false);
      card.success(0x35, fields("index", index));

      byte[] incorrect = index.clone();
      incorrect[1] = 20;
      assertError(
        card.transmit(0x34, fields("index", incorrect, "data", data)),
        "INVALID_PARAMETER"
      );

      incorrect = index.clone();
      incorrect[9] ^= 1;
      assertError(
        card.transmit(0x34, fields("index", incorrect, "data", data)),
        "INVALID_PARAMETER"
      );

      Assertions.assertArrayEquals(index, card.create(index, null, null, data, false));
    }
  }

  @Test
  public void randomKeysAreSecretAndInvalidLengthsCannotChangeTheCategory() {
    try (Card card = new Card(true)) {
      for (int length : new int[] { -1, 0, 256, 512, 32767 }) {
        assertError(
          card.transmit(0x38, fields("type", "hmac", "length", length)),
          "INVALID_PARAMETER"
        );
      }

      Assertions.assertEquals(
        0,
        card.success(0x30, fields()).reader().requireKey(ascii("items")).array()
      );

      for (int length : new int[] { 1, 32, 64, 255 }) {
        byte[] index = card.success(0x38, fields("type", "hmac", "length", length)).bytes("index");

        Assertions.assertEquals(5, index[0]);
        Assertions.assertEquals(length, index[1] & 0xFF);
        Assertions.assertTrue(
          card.success(0x31, fields("index", index)).reader().requireKey(ascii("secret")).bool()
        );
        assertError(card.transmit(0x32, fields("index", index)), "ACCESS_DENIED");
      }
    }
  }

  @Test
  public void setAndEncryptedTransferRetainExistingKeyAndSecretSemantics() {
    try (Card card = new Card(true)) {
      byte[] publicKey = card.publicKey();
      byte[] lookup = { 1, 2 };
      byte[] data = sequence(32);
      byte[] index = card.create("hmac", lookup, "original", data, true);
      byte[] replacement = data.clone();
      replacement[0] ^= 1;

      card.success(
        0x33,
        fields("index", index, "alias", "updated", "data", replacement, "secret", false)
      );

      Result metadata = card.success(0x31, fields("index", index));
      Assertions.assertArrayEquals(lookup, metadata.bytes("metadata"));
      Assertions.assertArrayEquals(
        ascii("updated"),
        metadata.reader().requireKey(ascii("alias")).text()
      );
      Assertions.assertArrayEquals(
        replacement,
        card.success(0x32, fields("index", index)).bytes("data")
      );

      card.authenticate(true);

      for (boolean secret : new boolean[] { false, true }) {
        card.success(0x33, fields("index", index, "secret", secret));
        byte[] ciphertext = card
          .success(0x36, fields("index", index, "recipientPublicKey", publicKey))
          .bytes("data");
        Map<String, Object> request = fields(
          "index",
          index,
          "senderPublicKey",
          publicKey,
          "metadata",
          lookup,
          "alias",
          "updated",
          "data",
          ciphertext
        );

        card.success(0x35, fields("index", index));
        card.success(0x37, request);
        card.success(0x37, request);

        Assertions.assertEquals(
          secret,
          card.success(0x31, fields("index", index)).reader().requireKey(ascii("secret")).bool()
        );

        if (secret) {
          assertError(card.transmit(0x32, fields("index", index)), "ACCESS_DENIED");
        } else {
          Assertions.assertArrayEquals(
            replacement,
            card.success(0x32, fields("index", index)).bytes("data")
          );
        }
      }
    }
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }
}
