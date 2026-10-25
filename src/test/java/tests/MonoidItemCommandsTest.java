package tests;

import static tests.MonoidItemTransferTest.assertData;
import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.assertMetadata;
import static tests.MonoidItemTransferTest.customIndex;
import static tests.MonoidItemTransferTest.fields;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoid.Text;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

public class MonoidItemCommandsTest {

  @Test
  public void selectingAbsentOptionalAppletsReturnsFileNotFound() {
    try (Card card = new Card(true)) {
      String[] aids = {
        // @inplate-line "{{hex MONOID_OTP_AID}}",
        "f06d6f6e6f69640501",
        // @inplate-line "{{hex MONOID_SECURITY_KEY_AID}}",
        "a0000006472f0001",
      };

      for (String aid : aids) {
        ResponseAPDU response = card.simulator.transmitCommand(
          new CommandAPDU(0, 0xA4, 4, 0, Hex.decode(aid))
        );
        Assertions.assertEquals(0x6A82, response.getSW());
        Assertions.assertEquals(0, response.getData().length);
        card.success(0x20, fields());
      }
    }
  }

  @Test
  public void explicitIndexCreateRejectsIdenticalAndDifferentItems() {
    try (Card card = new Card(true)) {
      byte[] index = customIndex(1);
      byte[] metadata = { 1, 2 };
      byte[] data = { 3, 4 };
      card.create(index, metadata, "original", data, false);

      for (boolean identical : new boolean[] { true, false }) {
        assertError(
          card.transmit(
            0x34,
            fields(
              "index",
              index,
              "metadata",
              identical ? metadata : new byte[] { 5 },
              "alias",
              identical ? "original" : "changed",
              "data",
              identical ? data : new byte[] { 6 },
              "secret",
              !identical
            )
          ),
          "EXISTS"
        );
        assertMetadata(card, index, metadata, "original", false);
        assertData(card, index, data);
      }

      Assertions.assertEquals(
        1,
        card.success(0x30, fields()).reader().requireKey(Text.items).array()
      );
    }
  }

  @Test
  public void digestIndexCreateRejectsIdenticalAndDifferentItems() {
    try (Card card = new Card(true)) {
      byte[] data = { 1, 2, 3 };
      byte[] index = card.create("hmac", null, "original", data, false);

      for (boolean explicit : new boolean[] { false, true }) {
        for (boolean identical : new boolean[] { true, false }) {
          assertError(
            card.transmit(
              0x34,
              fields(
                explicit ? "index" : "type",
                explicit ? index : "hmac",
                "alias",
                identical ? "original" : "changed",
                "data",
                data,
                "secret",
                !identical
              )
            ),
            "EXISTS"
          );
          assertMetadata(card, index, null, "original", false);
          assertData(card, index, data);
        }
      }

      Assertions.assertEquals(
        1,
        card.success(0x30, fields()).reader().requireKey(Text.items).array()
      );
    }
  }

  @Test
  public void randomKeyCollisionReturnsExists() {
    try (Card card = new Card(true)) {
      // Fill the entire one-byte key space so every random result collides.
      for (int value = 0; value < 256; value++) {
        card.create("hmac", null, null, new byte[] { (byte) value }, true);
      }

      assertError(card.transmit(0x38, fields("type", "hmac", "length", 1)), "EXISTS");
      Assertions.assertEquals(
        256,
        card.success(0x30, fields()).reader().requireKey(Text.items).array()
      );
    }
  }

  @Test
  public void removeReportsWhetherItDeletedAnItemAndPreservesAuthorization() {
    try (Card card = new Card(true)) {
      byte[] index = customIndex(1);
      byte[] missing = customIndex(2);
      card.create(index, null, null, new byte[] { 1 }, true);

      assertRemoved(card.success(0x35, fields("index", missing)), false);
      assertMetadata(card, index, null, null, true);

      card.reset();
      assertError(card.transmit(0x35, fields("index", index)), "UNAUTHORIZED");
      assertError(card.transmit(0x35, fields("index", missing)), "UNAUTHORIZED");
      card.authenticate(false);
      Assertions.assertEquals(0x6A80, card.transmit(0x35, fields("index", new byte[9])).status);
      assertMetadata(card, index, null, null, true);

      assertRemoved(card.success(0x35, fields("index", index)), true);
      assertRemoved(card.success(0x35, fields("index", index)), false);
      assertError(card.transmit(0x31, fields("index", index)), "NOT_FOUND");
      Assertions.assertEquals(
        0,
        card.success(0x30, fields()).reader().requireKey(Text.items).array()
      );
    }
  }

  private static void assertRemoved(Result result, boolean expected) {
    Assertions.assertEquals(1, result.size());
    Assertions.assertEquals(expected, result.reader().requireKey(Text.removed).bool());
  }
}
