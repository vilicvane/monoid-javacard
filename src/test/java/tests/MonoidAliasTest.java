package tests;

import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.assertISOError;
import static tests.MonoidItemTransferTest.assertMetadata;
import static tests.MonoidItemTransferTest.customIndex;
import static tests.MonoidItemTransferTest.fields;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoidlib.CBORBufferReader;
import monoidlib.CBORBufferWriter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

public class MonoidAliasTest {

  @Test
  public void settingAndClearingAliasRequireSecretAuthentication() {
    try (Card card = new Card(true)) {
      assertError(card.transmit(0x27, fields("alias", "card")), "ACCESS_DENIED");
      card.reset();
      assertError(card.transmit(0x27, fields("alias", "card")), "UNAUTHORIZED");
      assertNoAlias(card);

      card.authenticate(true);
      Assertions.assertEquals(0, card.success(0x27, fields("alias", "我的卡 🔑")).size());
      assertAlias(card, "我的卡 🔑");
      card.authenticate(false);
      assertError(card.transmit(0x27, fields("alias", "")), "ACCESS_DENIED");
      assertAlias(card, "我的卡 🔑");
      card.authenticate(true);
      Assertions.assertEquals(0, card.success(0x27, fields("alias", "")).size());
      assertNoAlias(card);
    }
  }

  @Test
  public void aliasLimitCountsUtf8BytesAndInvalidRequestsPreserveTheValue() {
    String alias = "🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑";
    Assertions.assertEquals(64, bytes(alias).length);

    try (Card card = new Card(true)) {
      card.authenticate(true);
      card.success(0x27, fields("alias", alias));
      assertAlias(card, alias);
      assertError(card.transmit(0x27, fields("alias", alias + "a")), "INVALID_PARAMETER");
      assertISOError(card.transmit(0x27, fields()), 0x6A80);
      assertISOError(card.transmit(0x27, fields("alias", bytes("card"))), 0x6A80);
      assertAlias(card, alias);
    }
  }

  @Test
  public void aliasBytesAreStoredWithoutEncodingValidation() {
    try (Card card = new Card(true)) {
      card.authenticate(true);
      byte[] alias = { (byte) 0xFF, (byte) 0xC0, 0 };
      CBORBufferWriter writer = new CBORBufferWriter();
      writer.map((short) 1);
      writer.text(bytes("alias"));
      writer.text(alias);

      ResponseAPDU response = card.simulator.transmitCommand(
        new CommandAPDU(0, 0x27, 0, 0, writer.getDataBuffer())
      );
      new Result(response.getData(), response.getSW(), 1, 1).assertSuccess();
      Assertions.assertArrayEquals(
        alias,
        card.success(0x20, fields()).reader().requireKey(bytes("alias")).text()
      );
    }
  }

  @Test
  public void aliasSurvivesPowerResetMonoidReplacementAndCommandReset() {
    try (Card card = new Card(true)) {
      card.authenticate(true);
      card.success(0x27, fields("alias", "retained"));
      byte[] id = card.safeId();
      byte[] publicKey = card.publicKey();

      card.reset();
      assertAlias(card, "retained");
      card.reinstallMonoid();
      assertAlias(card, "retained");
      Assertions.assertArrayEquals(publicKey, card.publicKey());
      card.success(0xFF, fields());
      card.reset();
      assertAlias(card, "retained");
      Assertions.assertArrayEquals(id, card.safeId());
      Assertions.assertFalse(Arrays.equals(publicKey, card.publicKey()));
    }

    try (Card recreated = new Card(true)) {
      assertNoAlias(recreated);
    }
  }

  @Test
  public void bundleEnrollmentAndItemTransferKeepCardAliasesLocal() {
    try (Card source = new Card(false); Card target = new Card(false)) {
      byte[] sourceKey = source.bootstrapPublicKey();
      byte[] targetKey = target.bootstrapPublicKey();
      source.installMonoid();
      source.authenticate(true);
      source.success(0x27, fields("alias", "source"));
      Result created = source.success(0x23, fields("publicKeys", new byte[][] { targetKey }));
      byte[] bundle = created.bytes("bundle");
      CBORBufferReader reader = created.reader();
      Assertions.assertEquals(1, reader.requireKey(bytes("data")).array());
      Assertions.assertTrue(reader.index((short) 0));
      byte[] packet = reader.bytes().clone();
      Assertions.assertTrue(
        source.success(0x20, fields()).reader().requireKey(bytes("allowPeerExtension")).bool()
      );
      source.success(0x27, fields("alias", "renamed"));
      Assertions.assertArrayEquals(bundle, source.success(0x20, fields()).bytes("bundle"));
      byte[] index = customIndex(248);
      source.create(index, null, "条目 🔑", new byte[] { 1, 2, 3 }, false);
      Result item = source.success(0x36, fields("index", index));
      Assertions.assertEquals(2, item.size());
      String itemAlias = new String(
        item.reader().requireKey(bytes("alias")).text(),
        StandardCharsets.UTF_8
      );
      source.uninstallMonoid();

      target.installMonoid();
      target.authenticate(true);
      target.success(0x27, fields("alias", "target"));
      Assertions.assertArrayEquals(
        bundle,
        target.success(0x24, fields("publicKey", sourceKey, "data", packet)).bytes("bundle")
      );
      target.success(0x37, fields("index", index, "alias", itemAlias, "data", item.bytes("data")));
      assertAlias(target, "target");
      assertMetadata(target, index, null, "条目 🔑", false);
      target.uninstallMonoid();

      source.installMonoid();
      assertAlias(source, "renamed");
    }
  }

  private static void assertNoAlias(Card card) {
    Assertions.assertFalse(card.success(0x20, fields()).reader().requireKey(bytes("alias")).bool());
  }

  private static void assertAlias(Card card, String alias) {
    Assertions.assertArrayEquals(
      bytes(alias),
      card.success(0x20, fields()).reader().requireKey(bytes("alias")).text()
    );
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }
}
