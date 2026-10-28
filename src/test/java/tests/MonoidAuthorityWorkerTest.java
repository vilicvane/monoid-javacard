package tests;

import static tests.MonoidItemTransferTest.assertISOError;
import static tests.MonoidItemTransferTest.fields;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

@Tag("authority")
public class MonoidAuthorityWorkerTest {

  @Test
  public void actualWorkerPacketsMatchBundleHashAndEnforcePolicy() throws Exception {
    try (Worker worker = new Worker(); Card peer = new Card(false)) {
      byte[] peerKey = peer.bootstrapPublicKey();

      for (boolean allowPeerExtension : new boolean[] { false, true }) {
        try (Card card = new Card(true, worker.installationParameters())) {
          assertPolicy(card, false);
          card.authenticate(true);

          Packet packet = worker.issue(card.publicKey(), allowPeerExtension, "group");
          Assertions.assertArrayEquals(
            packet.bundle,
            card.success(0x24, packet.request()).bytes("bundle")
          );
          Assertions.assertArrayEquals(packet.bundle, card.success(0x20, fields()).bytes("bundle"));
          assertPolicy(card, allowPeerExtension);

          if (allowPeerExtension) {
            card.success(0x25, fields("publicKey", peerKey));
          } else {
            assertISOError(card.transmit(0x25, fields("publicKey", peerKey)), 0x6985);
            assertISOError(card.transmit(0x26, fields("data", new byte[0])), 0x6985);
          }

          Packet conflict = worker.issue(card.publicKey(), allowPeerExtension, "other-group");
          assertISOError(card.transmit(0x24, conflict.request()), 0x6985);
          Assertions.assertArrayEquals(packet.bundle, card.success(0x20, fields()).bytes("bundle"));

          card.reset();
          assertPolicy(card, allowPeerExtension);
          card.authenticate(true);
          Assertions.assertArrayEquals(
            packet.bundle,
            card.success(0x24, packet.request()).bytes("bundle")
          );
          card.success(0xFF, fields());
          assertPolicy(card, false);
        }
      }
    }
  }

  @Test
  public void actualWorkerPacketRejectsDifferentAuthorityAndRecipient() throws Exception {
    try (Worker worker = new Worker(); Card peer = new Card(false)) {
      byte[] peerKey = peer.bootstrapPublicKey();

      try (Card card = new Card(true, worker.installationParameters())) {
        card.authenticate(true);
        Packet packet = worker.issue(card.publicKey(), false, "group");
        Map<String, Object> wrongAuthority = packet.request();
        wrongAuthority.put("publicKey", peerKey);

        assertISOError(card.transmit(0x24, wrongAuthority), 0x6985);
        assertISOError(
          card.transmit(0x24, worker.issue(peerKey, false, "group").request()),
          0x6985
        );
        Assertions.assertFalse(
          card.success(0x20, fields()).reader().requireKey(bytes("bundle")).bool()
        );
        assertPolicy(card, false);
        Assertions.assertArrayEquals(
          packet.bundle,
          card.success(0x24, packet.request()).bytes("bundle")
        );
      }
    }
  }

  private static void assertPolicy(Card card, boolean expected) {
    Result hello = card.success(0x20, fields());
    Assertions.assertEquals(
      expected,
      hello.reader().requireKey(bytes("allowPeerExtension")).bool()
    );
    Assertions.assertFalse(hello.reader().key(bytes("authorityPublicKey")));
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  private static final class Packet {

    final byte[] publicKey;
    final byte[] data;
    final byte[] bundle;

    Packet(String line) {
      String[] fields = line.split(" ");
      Assertions.assertEquals(3, fields.length, line);
      publicKey = Hex.decode(fields[0]);
      data = Hex.decode(fields[1]);
      bundle = Hex.decode(fields[2]);
    }

    Map<String, Object> request() {
      return fields("publicKey", publicKey, "data", data);
    }
  }

  private static final class Worker implements AutoCloseable {

    private final Process process;
    private final BufferedReader output;
    private final Writer input;
    private final byte[] publicKey;

    Worker() throws Exception {
      process = new ProcessBuilder("node", "src/test/js/authority-bundle-worker.mjs")
        .redirectError(ProcessBuilder.Redirect.INHERIT)
        .start();
      output = new BufferedReader(
        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)
      );
      input = new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8);
      publicKey = Hex.decode(readLine());
    }

    byte[] installationParameters() {
      byte[] url = bytes("https://authority.example");
      byte[] parameters = new byte[1 + publicKey.length + url.length];
      parameters[0] = 2;
      System.arraycopy(publicKey, 0, parameters, 1, publicKey.length);
      System.arraycopy(url, 0, parameters, 1 + publicKey.length, url.length);
      return parameters;
    }

    Packet issue(byte[] recipient, boolean allowPeerExtension, String group) throws Exception {
      input.write(Hex.toHexString(recipient) + " " + allowPeerExtension + " " + group + "\n");
      input.flush();
      return new Packet(readLine());
    }

    private String readLine() throws Exception {
      String line = output.readLine();
      Assertions.assertNotNull(
        line,
        "Authority Worker harness exited; see stderr (requires sibling monoid/workers/authority dependencies)"
      );
      return line;
    }

    @Override
    public void close() throws Exception {
      try {
        input.close();
        Assertions.assertTrue(
          process.waitFor(10, TimeUnit.SECONDS),
          "Authority Worker did not exit"
        );
        Assertions.assertEquals(0, process.exitValue());
      } finally {
        process.destroyForcibly();
        output.close();
      }
    }
  }
}
