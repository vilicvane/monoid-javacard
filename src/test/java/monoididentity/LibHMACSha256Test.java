package monoididentity;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import javacard.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LibHMACSha256Test {

  @Test
  public void matchesKnownSha256HmacVectors() throws Exception {
    byte[] firstKey = new byte[20];
    Arrays.fill(firstKey, (byte) 0x0B);
    byte[][] keys = { firstKey, "Jefe".getBytes(StandardCharsets.US_ASCII) };
    byte[][] messages = {
      "Hi There".getBytes(StandardCharsets.US_ASCII),
      "what do ya want for nothing?".getBytes(StandardCharsets.US_ASCII),
    };
    byte[][] expected = {
      Hex.decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
      Hex.decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    };
    MessageDigest digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    byte[] block = new byte[LibHMACSha256.BLOCK_LENGTH];

    for (int index = 0; index < keys.length; index++) {
      byte[] out = new byte[MessageDigest.LENGTH_SHA_256];
      LibHMACSha256.begin(digest, block, keys[index], (short) 0, (short) keys[index].length);
      digest.doFinal(messages[index], (short) 0, (short) messages[index].length, out, (short) 0);
      LibHMACSha256.finish(digest, block, out, (short) 0);

      Assertions.assertArrayEquals(expected[index], out);
      Assertions.assertArrayEquals(onHost(keys[index], messages[index]), out);
    }
  }

  @Test
  public void reusedWorkspaceMatchesHostForEmptySaltStreamingAndOffsets() throws Exception {
    Random random = new Random(0x5AFE256);
    MessageDigest digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    byte[] block = new byte[LibHMACSha256.BLOCK_LENGTH];

    for (int keyLength : new int[] { 0, 1, 20, 32 }) {
      for (int length : new int[] { 0, 1, 32, 55, 56, 63, 64, 65, 128 }) {
        byte[] key = new byte[keyLength];
        byte[] message = new byte[length];
        random.nextBytes(key);
        random.nextBytes(message);
        byte[] keyInput = padded(key, 3, 4);
        byte[] messageInput = padded(message, 5, 7);
        byte[] output = padded(new byte[MessageDigest.LENGTH_SHA_256], 2, 6);
        short split = (short) (length / 2);

        LibHMACSha256.begin(digest, block, keyInput, (short) 3, (short) keyLength);
        digest.update(messageInput, (short) 5, split);
        digest.doFinal(
          messageInput,
          (short) (5 + split),
          (short) (length - split),
          output,
          (short) 2
        );
        LibHMACSha256.finish(digest, block, output, (short) 2);

        Assertions.assertArrayEquals(padded(onHost(key, message), 2, 6), output);
        Assertions.assertArrayEquals(padded(key, 3, 4), keyInput);
        Assertions.assertArrayEquals(padded(message, 5, 7), messageInput);
      }
    }
  }

  @Test
  public void innerDigestMayOverwriteTheKeyBeforeFinishing() throws Exception {
    byte[] key = new byte[32];
    byte[] message = new byte[73];
    Random random = new Random(0x1D3A71);
    random.nextBytes(key);
    random.nextBytes(message);
    byte[] expected = onHost(key, message);
    MessageDigest digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    byte[] block = new byte[LibHMACSha256.BLOCK_LENGTH];

    LibHMACSha256.begin(digest, block, key, (short) 0, (short) key.length);
    digest.doFinal(message, (short) 0, (short) message.length, key, (short) 0);
    LibHMACSha256.finish(digest, block, key, (short) 0);

    Assertions.assertArrayEquals(expected, key);
  }

  private static byte[] onHost(byte[] key, byte[] message) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    // An empty HMAC key and a zero-filled 32-byte key have the same padded block.
    mac.init(new SecretKeySpec(key.length == 0 ? new byte[32] : key, "HmacSHA256"));
    return mac.doFinal(message);
  }

  private static byte[] padded(byte[] value, int prefix, int suffix) {
    byte[] buffer = new byte[prefix + value.length + suffix];
    Arrays.fill(buffer, (byte) 0xA5);
    System.arraycopy(value, 0, buffer, prefix, value.length);
    return buffer;
  }
}
