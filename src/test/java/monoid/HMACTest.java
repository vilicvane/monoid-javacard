package monoid;

import java.lang.reflect.Field;
import java.util.Arrays;
import javacard.framework.JCSystem;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class HMACTest {

  @Test
  public void emptyShortAndLongKeysMatchIndependentHmacAcrossBlockBoundaries() throws Exception {
    HMAC hmac = new HMAC();

    for (byte algorithm = Monoid.HMAC_SHA1; algorithm <= Monoid.HMAC_SHA512; algorithm++) {
      for (int keyLength : new int[] { 0, 1, 20, 63, 64, 65, 127, 128, 129, 131, 255 }) {
        for (int messageLength : new int[] { 0, 8, 63, 64, 127, 128, 129, 257 }) {
          byte[] message = sequence(messageLength);

          check(hmac, algorithm, sequence(keyLength), message, (short) 0, (short) message.length);
        }
      }
    }
  }

  @Test
  public void algorithmAndKeyChangesReuseOneTransientWorkspace() throws Exception {
    HMAC hmac = new HMAC();
    byte[] message = sequence(137);
    Object sharedBlock = null;

    for (byte algorithm : new byte[] {
      Monoid.HMAC_SHA512,
      Monoid.HMAC_SHA1,
      Monoid.HMAC_SHA256,
      Monoid.HMAC_SHA512,
    }) {
      for (int keyLength : new int[] { 255, 1, 128, 20, 64, 65, 0 }) {
        check(hmac, algorithm, sequence(keyLength), message, (short) 0, (short) message.length);

        Object block = field(hmac, "block");

        Assertions.assertEquals(JCSystem.CLEAR_ON_RESET, JCSystem.isTransient(block));
        Assertions.assertEquals(128, ((byte[]) block).length);

        if (sharedBlock == null) {
          sharedBlock = block;
        } else {
          Assertions.assertSame(sharedBlock, block);
        }
      }
    }
  }

  @Test
  public void messageSlicesLeaveInputsUnchanged() throws Exception {
    HMAC hmac = new HMAC();
    byte[] key = sequence(131);
    byte[] message = sequence(150);
    byte[] originalKey = key.clone();
    byte[] originalMessage = message.clone();

    for (byte algorithm = Monoid.HMAC_SHA1; algorithm <= Monoid.HMAC_SHA512; algorithm++) {
      check(hmac, algorithm, key, message, (short) 7, (short) 129);

      Assertions.assertArrayEquals(originalKey, key);
      Assertions.assertArrayEquals(originalMessage, message);
    }
  }

  private static void check(
    HMAC hmac,
    byte algorithm,
    byte[] key,
    byte[] message,
    short offset,
    short length
  ) throws Exception {
    String name = algorithm == Monoid.HMAC_SHA1
      ? "HmacSHA1"
      : algorithm == Monoid.HMAC_SHA256 ? "HmacSHA256" : "HmacSHA512";
    Mac oracle = Mac.getInstance(name);

    // HMAC pads both an empty key and one zero byte to the same all-zero block.
    oracle.init(new SecretKeySpec(key.length == 0 ? new byte[1] : key, name));
    oracle.update(message, offset, length);

    byte[] result = hmac.calculate(algorithm, key, message, offset, length);

    Assertions.assertArrayEquals(
      oracle.doFinal(),
      Arrays.copyOf(result, hmac.getLength(algorithm))
    );
  }

  private static Object field(HMAC hmac, String name) throws Exception {
    Field field = HMAC.class.getDeclaredField(name);
    field.setAccessible(true);

    return field.get(hmac);
  }

  private static byte[] sequence(int length) {
    byte[] result = new byte[length];

    for (int index = 0; index < length; index++) {
      result[index] = (byte) (index * 7 + 3);
    }

    return result;
  }
}
