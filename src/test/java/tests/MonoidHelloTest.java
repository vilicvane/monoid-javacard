package tests;

import static tests.MonoidItemTransferTest.fields;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import monoidlib.CBORBufferReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

public class MonoidHelloTest {

  @Test
  public void helloReportsNoAuthorityBeforePINInitialization() {
    try (Card card = new Card(false)) {
      card.installMonoid(false);

      Result response = card.success(0x20, fields());
      Assertions.assertEquals(6, response.size());
      Assertions.assertFalse(response.reader().requireKey(bytes("authority")).bool());

      CBORBufferReader reader = response.reader();
      reader.requireKey(bytes("pins")).map();

      Assertions.assertFalse(reader.requireKey(bytes("access")).bool());
      Assertions.assertFalse(reader.requireKey(bytes("secret")).bool());
    }
  }

  @Test
  public void helloPreservesAuthorityAcrossPowerAndAppletReset() throws Exception {
    AuthorityBundleIssuer issuer = new AuthorityBundleIssuer();
    String url = "https://authority.example/用户/";

    try (Card card = new Card(true, issuer.installationParameters(url))) {
      card.reset();

      Result before = card.success(0x20, fields());
      assertAuthority(before, url);

      byte[] id = before.bytes("id");
      byte[] publicKey = before.bytes("publicKey");

      card.success(0xFF, fields());
      card.reset();

      Result after = card.success(0x20, fields());
      assertAuthority(after, url);
      Assertions.assertArrayEquals(id, after.bytes("id"));
      Assertions.assertFalse(Arrays.equals(publicKey, after.bytes("publicKey")));
    }
  }

  @Test
  public void longAuthorityURLSurvivesFragmentedResponseAndMonoidReplacement() throws Exception {
    AuthorityBundleIssuer issuer = new AuthorityBundleIssuer();
    StringBuilder urlBuilder = new StringBuilder("https://authority.example/");

    while (urlBuilder.length() < 177) {
      urlBuilder.append('a');
    }

    String url = urlBuilder.toString();

    try (Card card = new Card(true, issuer.installationParameters(url))) {
      card.reset();

      Result before = card.success(0x20, fields());
      assertAuthority(before, url);
      Assertions.assertTrue(before.responseFrames > 1);

      byte[] id = before.bytes("id");
      byte[] publicKey = before.bytes("publicKey");

      card.reinstallMonoid();

      Result after = card.success(0x20, fields());
      assertAuthority(after, url);
      Assertions.assertTrue(after.responseFrames > 1);
      Assertions.assertArrayEquals(id, after.bytes("id"));
      Assertions.assertArrayEquals(publicKey, after.bytes("publicKey"));
    }
  }

  private static void assertAuthority(Result response, String url) {
    Assertions.assertEquals(6, response.size());
    Assertions.assertArrayEquals(
      url.getBytes(StandardCharsets.UTF_8),
      response.reader().requireKey(bytes("authority")).text()
    );
    Assertions.assertFalse(response.reader().key(bytes("authorityPublicKey")));
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }
}
