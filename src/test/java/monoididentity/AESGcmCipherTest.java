package monoididentity;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.util.Arrays;
import java.util.Random;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AESGcmCipherTest {

  private static final byte[] KEY = Hex.decode("feffe9928665731c6d6a8f9467308308");
  private static final byte[] NONCE = Hex.decode("cafebabefacedbaddecaf888");

  @Test
  public void matchesNISTEmptyAADVectors() {
    // NIST AES-GCM examples #1 and #2: 128-bit key/tag, 96-bit IV, empty AAD.
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
    byte[][] plaintexts = {
      new byte[0],
      Hex.decode(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
      ),
    };
    byte[][] encrypted = {
      Hex.decode("3247184b3c4f69a44dbcd22887bbb418"),
      Hex.decode(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" +
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985" +
        "4d5c2af327cd64a62cf35abd2ba6fab4"
      ),
    };
    AESGcmCipher cipher = new AESGcmCipher();
    AESKey key = key(KEY);

    for (int index = 0; index < plaintexts.length; index++) {
      Assertions.assertArrayEquals(
        encrypted[index],
        encrypt(cipher, key, NONCE, plaintexts[index])
      );
      Assertions.assertArrayEquals(
        plaintexts[index],
        decrypt(cipher, key, NONCE, encrypted[index])
      );
    }
  }

  @Test
  public void blockBoundariesMatchIndependentHostEncryption() throws Exception {
    Random random = new Random(0x5AFE2026);
    AESGcmCipher cipher = new AESGcmCipher();

    for (int length : new int[] { 0, 1, 15, 16, 17, 31, 32, 33, 64 }) {
      byte[] key = new byte[16];
      byte[] nonce = new byte[12];
      byte[] plaintext = new byte[length];
      random.nextBytes(key);
      random.nextBytes(nonce);
      random.nextBytes(plaintext);
      byte[] expected = encryptOnHost(key, nonce, plaintext);
      AESKey cardKey = key(key);

      Assertions.assertArrayEquals(expected, encrypt(cipher, cardKey, nonce, plaintext));
      Assertions.assertArrayEquals(plaintext, decrypt(cipher, cardKey, nonce, expected));
    }
  }

  @Test
  public void respectsInputOutputNonceAndTagOffsets() throws Exception {
    byte[] plaintext = new byte[33];
    new Random(0xECD5A).nextBytes(plaintext);
    byte[] expected = encryptOnHost(KEY, NONCE, plaintext);
    byte[] input = padded(plaintext, 5, 3);
    byte[] nonce = padded(NONCE, 3, 4);
    byte[] output = padded(new byte[expected.length], 7, 5);
    AESGcmCipher cipher = new AESGcmCipher();
    AESKey key = key(KEY);
    cipher.init(key, Cipher.MODE_ENCRYPT, nonce, (short) 3);

    Assertions.assertEquals(
      plaintext.length,
      cipher.doFinal(input, (short) 5, (short) plaintext.length, output, (short) 7)
    );
    Assertions.assertEquals(16, cipher.retrieveTag(output, (short) (7 + plaintext.length)));
    Assertions.assertArrayEquals(padded(expected, 7, 5), output);
    Assertions.assertArrayEquals(padded(plaintext, 5, 3), input);
    Assertions.assertArrayEquals(padded(NONCE, 3, 4), nonce);

    byte[] decrypted = padded(new byte[plaintext.length], 4, 6);
    cipher.init(key, Cipher.MODE_DECRYPT, nonce, (short) 3);
    Assertions.assertEquals(
      plaintext.length,
      cipher.doFinal(output, (short) 7, (short) plaintext.length, decrypted, (short) 4)
    );
    Assertions.assertTrue(cipher.verifyTag(output, (short) (7 + plaintext.length)));
    Assertions.assertArrayEquals(padded(plaintext, 4, 6), decrypted);
  }

  @Test
  public void encryptsAndDecryptsInPlace() throws Exception {
    AESGcmCipher cipher = new AESGcmCipher();
    AESKey key = key(KEY);

    // Byte 4064 starts counter 256, carrying into the preceding counter byte.
    for (int length : new int[] {
      0,
      1,
      15,
      16,
      17,
      31,
      32,
      33,
      64,
      256,
      1024,
      2048,
      4063,
      4064,
      4065,
      4096,
    }) {
      byte[] plaintext = new byte[length];
      new Random(length).nextBytes(plaintext);
      byte[] expected = encryptOnHost(KEY, NONCE, plaintext);
      byte[] buffer = padded(Arrays.copyOf(plaintext, length + 16), 5, 7);
      cipher.init(key, Cipher.MODE_ENCRYPT, NONCE, (short) 0);

      Assertions.assertEquals(
        length,
        cipher.doFinal(buffer, (short) 5, (short) length, buffer, (short) 5)
      );
      cipher.retrieveTag(buffer, (short) (5 + length));
      Assertions.assertArrayEquals(padded(expected, 5, 7), buffer);

      cipher.init(key, Cipher.MODE_DECRYPT, NONCE, (short) 0);
      Assertions.assertEquals(
        length,
        cipher.doFinal(buffer, (short) 5, (short) length, buffer, (short) 5)
      );
      Assertions.assertTrue(cipher.verifyTag(buffer, (short) (5 + length)));
      System.arraycopy(plaintext, 0, expected, 0, length);
      Assertions.assertArrayEquals(padded(expected, 5, 7), buffer);
    }
  }

  @Test
  public void largerMessagesRejectChangesAcrossCounterCarry() throws Exception {
    byte[] plaintext = new byte[4096];
    new Random(0x5AFE4096).nextBytes(plaintext);
    byte[] encrypted = encryptOnHost(KEY, NONCE, plaintext);
    AESGcmCipher cipher = new AESGcmCipher();
    AESKey key = key(KEY);

    for (int offset : new int[] { 0, 4063, 4064, plaintext.length - 1 }) {
      byte[] corrupted = encrypted.clone();
      corrupted[offset] ^= 1;
      cipher.init(key, Cipher.MODE_DECRYPT, NONCE, (short) 0);
      Assertions.assertEquals(
        plaintext.length,
        cipher.doFinal(corrupted, (short) 0, (short) plaintext.length, corrupted, (short) 0)
      );
      Assertions.assertFalse(cipher.verifyTag(corrupted, (short) plaintext.length));
    }

    Assertions.assertArrayEquals(plaintext, decrypt(cipher, key, NONCE, encrypted));
    Assertions.assertArrayEquals(
      encryptOnHost(KEY, NONCE, new byte[0]),
      encrypt(cipher, key, NONCE, new byte[0])
    );
  }

  @Test
  public void reinitializationReplacesKeyNonceAndPreviousState() throws Exception {
    AESGcmCipher cipher = new AESGcmCipher();
    AESKey key = key(KEY);
    byte[] otherKey = KEY.clone();
    byte[] otherNonce = NONCE.clone();
    otherKey[0] ^= 1;
    otherNonce[0] ^= 1;
    byte[][] keys = { KEY, KEY, otherKey, otherKey, KEY };
    byte[][] nonces = { NONCE, otherNonce, otherNonce, NONCE, NONCE };
    int[] lengths = { 32, 0, 1, 33, 17 };

    for (int index = 0; index < keys.length; index++) {
      byte[] plaintext = new byte[lengths[index]];
      Arrays.fill(plaintext, (byte) index);
      key.setKey(keys[index], (short) 0);
      byte[] expected = encryptOnHost(keys[index], nonces[index], plaintext);

      Assertions.assertArrayEquals(expected, encrypt(cipher, key, nonces[index], plaintext));
      Assertions.assertArrayEquals(plaintext, decrypt(cipher, key, nonces[index], expected));
    }
  }

  @Test
  public void checksEveryTagByteAndAllowsRepeatedVerification() throws Exception {
    byte[] plaintext = new byte[33];
    byte[] encrypted = encryptOnHost(KEY, NONCE, plaintext);
    AESGcmCipher cipher = new AESGcmCipher();
    decrypt(cipher, key(KEY), NONCE, encrypted);
    byte[] tag = Arrays.copyOfRange(encrypted, plaintext.length, encrypted.length);

    for (int index = 0; index < tag.length; index++) {
      tag[index] ^= 1;
      Assertions.assertFalse(cipher.verifyTag(tag, (short) 0));
      tag[index] ^= 1;
      Assertions.assertTrue(cipher.verifyTag(tag, (short) 0));
    }
  }

  @Test
  public void rejectsChangedCiphertextAndNonce() throws Exception {
    byte[] plaintext = new byte[33];
    byte[] encrypted = encryptOnHost(KEY, NONCE, plaintext);
    AESGcmCipher cipher = new AESGcmCipher();
    AESKey key = key(KEY);

    for (int offset : new int[] { 0, plaintext.length - 1 }) {
      byte[] corrupted = encrypted.clone();
      corrupted[offset] ^= 1;
      cipher.init(key, Cipher.MODE_DECRYPT, NONCE, (short) 0);
      cipher.doFinal(
        corrupted,
        (short) 0,
        (short) plaintext.length,
        new byte[plaintext.length],
        (short) 0
      );
      Assertions.assertFalse(cipher.verifyTag(corrupted, (short) plaintext.length));
    }

    byte[] nonce = NONCE.clone();
    nonce[0] ^= 1;
    cipher.init(key, Cipher.MODE_DECRYPT, nonce, (short) 0);
    cipher.doFinal(
      encrypted,
      (short) 0,
      (short) plaintext.length,
      new byte[plaintext.length],
      (short) 0
    );
    Assertions.assertFalse(cipher.verifyTag(encrypted, (short) plaintext.length));
  }

  private static AESKey key(byte[] data) {
    AESKey key = (AESKey) KeyBuilder.buildKey(
      KeyBuilder.TYPE_AES,
      KeyBuilder.LENGTH_AES_128,
      false
    );
    key.setKey(data, (short) 0);

    return key;
  }

  private static byte[] encrypt(AESGcmCipher cipher, AESKey key, byte[] nonce, byte[] plaintext) {
    byte[] encrypted = new byte[plaintext.length + 16];
    cipher.init(key, Cipher.MODE_ENCRYPT, nonce, (short) 0);
    Assertions.assertEquals(
      plaintext.length,
      cipher.doFinal(plaintext, (short) 0, (short) plaintext.length, encrypted, (short) 0)
    );
    Assertions.assertEquals(16, cipher.retrieveTag(encrypted, (short) plaintext.length));

    return encrypted;
  }

  private static byte[] decrypt(AESGcmCipher cipher, AESKey key, byte[] nonce, byte[] encrypted) {
    byte[] plaintext = new byte[encrypted.length - 16];
    cipher.init(key, Cipher.MODE_DECRYPT, nonce, (short) 0);
    Assertions.assertEquals(
      plaintext.length,
      cipher.doFinal(encrypted, (short) 0, (short) plaintext.length, plaintext, (short) 0)
    );

    for (int round = 0; round < 3; round++) {
      Assertions.assertTrue(cipher.verifyTag(encrypted, (short) plaintext.length));
    }

    return plaintext;
  }

  private static byte[] encryptOnHost(byte[] key, byte[] nonce, byte[] plaintext) throws Exception {
    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
      javax.crypto.Cipher.ENCRYPT_MODE,
      new SecretKeySpec(key, "AES"),
      new GCMParameterSpec(128, nonce)
    );

    return cipher.doFinal(plaintext);
  }

  private static byte[] padded(byte[] data, int prefix, int suffix) {
    byte[] buffer = new byte[prefix + data.length + suffix];
    Arrays.fill(buffer, (byte) 0x5A);
    System.arraycopy(data, 0, buffer, prefix, data.length);

    return buffer;
  }
}
