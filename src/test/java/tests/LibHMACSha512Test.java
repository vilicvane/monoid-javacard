package tests;

import com.licel.jcardsim.base.SimulatorSystem;
import java.lang.reflect.Field;
import java.util.Arrays;
import javacard.security.HMACKey;
import javacard.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import monoid.LibHMACSha512;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LibHMACSha512Test {

  @AfterEach
  public void dispose() {
    LibHMACSha512.dispose();
  }

  @Test
  public void selectedBackendSupportsOverlappingKeyAndOutput() throws Exception {
    LibHMACSha512.init();
    Field signature = LibHMACSha512.class.getDeclaredField("sharedSignature");
    signature.setAccessible(true);
    Assertions.assertNotNull(signature.get(null));
    Field key = LibHMACSha512.class.getDeclaredField("sharedKey");
    key.setAccessible(true);
    Assertions.assertTrue(((HMACKey) key.get(null)).getSize() >= 512);
    checkOverlappingBuffers();
    Field block = LibHMACSha512.class.getDeclaredField("sharedBlock");
    block.setAccessible(true);
    Assertions.assertNull(block.get(null));
  }

  @Test
  public void softwareBackendSupportsOverlappingKeyAndOutput() throws Exception {
    // Exercise the card's fallback even if the simulator supports native HMAC.
    LibHMACSha512.dispose();
    Field digest = LibHMACSha512.class.getDeclaredField("sharedDigest");
    digest.setAccessible(true);
    digest.set(null, MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false));
    checkOverlappingBuffers();
    Field block = LibHMACSha512.class.getDeclaredField("sharedBlock");
    block.setAccessible(true);
    Object previous = block.get(null);
    Assertions.assertNotNull(previous);
    checkOverlappingBuffers();
    Assertions.assertSame(previous, block.get(null));
  }

  private void checkOverlappingBuffers() throws Exception {
    byte[] buffer = new byte[96];
    byte[] block = new byte[LibHMACSha512.BLOCK_BYTES];

    for (boolean suppliedWorkspace : new boolean[] { false, true }) {
      for (short keyOffset : new short[] { 0, 32 }) {
        for (short keyLength : new short[] { 32, 64 }) {
          for (int index = 0; index < buffer.length; index++) {
            buffer[index] = (byte) (index * 7);
          }

          Mac oracle = Mac.getInstance("HmacSHA512");
          oracle.init(
            new SecretKeySpec(
              Arrays.copyOfRange(buffer, keyOffset, keyOffset + keyLength),
              "HmacSHA512"
            )
          );
          byte[] expected = oracle.doFinal(Arrays.copyOfRange(buffer, 5, 42));

          if (suppliedWorkspace) {
            LibHMACSha512.digest(
              buffer,
              keyOffset,
              keyLength,
              buffer,
              (short) 5,
              (short) 37,
              buffer,
              (short) 0,
              block
            );
          } else {
            LibHMACSha512.digest(
              buffer,
              keyOffset,
              keyLength,
              buffer,
              (short) 5,
              (short) 37,
              buffer,
              (short) 0
            );
          }

          Assertions.assertArrayEquals(expected, Arrays.copyOf(buffer, 64));
          SimulatorSystem.instance().reset();
        }
      }
    }
  }
}
