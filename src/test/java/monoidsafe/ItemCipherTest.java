package monoidsafe;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import monoidsafeidentity.CommunicationCipher;
import monoidsafeidentity.LibSECP256r1;
import monoidsafeidentity.SafeIdentityShareable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ItemCipherTest {

  private static final byte[] INDEX = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
  private static final byte[] KEY = { 1, 2, 3 };
  private static final byte[] ALIAS = "\u6d4b\u8bd5\u6761\u76ee".getBytes(StandardCharsets.UTF_8);

  @Test
  public void exportMatchesIndependentHostKeyDerivationAndGcm() throws Exception {
    TestIdentity sender = new TestIdentity(1);
    TestIdentity recipient = new TestIdentity(2);
    ItemCipher cipher = new ItemCipher();

    for (boolean secret : new boolean[] { false, true }) {
      for (int length : new int[] { 0, 14, 15, 30, 31, 32, 128, 368, 369, 1024, 4096 }) {
        SafeItem item = item(bytes(length), secret);
        byte[] encrypted = cipher.encrypt(sender, item, recipient.getPublicKey());

        Assertions.assertEquals(length + 144, encrypted.length);
        Assertions.assertEquals(1, encrypted[0]);
        Assertions.assertEquals(
          encrypted.length <= 512 ? JCSystem.CLEAR_ON_RESET : JCSystem.NOT_A_TRANSIENT_OBJECT,
          JCSystem.isTransient(encrypted)
        );
        Assertions.assertNotSame(item.data, encrypted);
        Assertions.assertArrayEquals(context(item), sender.lastContext);
        Assertions.assertArrayEquals(
          plaintext(item),
          cryptOnHost(
            Cipher.DECRYPT_MODE,
            sender.lastKey,
            context(item),
            Arrays.copyOfRange(encrypted, 114, 126),
            Arrays.copyOfRange(encrypted, 126, encrypted.length)
          )
        );
        Assertions.assertArrayEquals(bytes(length), item.data);
      }
    }
  }

  @Test
  public void importsIndependentHostCiphertext() throws Exception {
    TestIdentity sender = new TestIdentity(1);
    TestIdentity recipient = new TestIdentity(2);
    ItemCipher cipher = new ItemCipher();

    for (boolean secret : new boolean[] { false, true }) {
      for (int length : new int[] {
        0,
        1,
        14,
        15,
        16,
        30,
        31,
        32,
        127,
        256,
        510,
        511,
        1024,
        4096,
      }) {
        SafeItem item = item(bytes(length), secret);
        byte[] encrypted = encryptOnHost(sender, recipient, item);
        byte[] original = encrypted.clone();
        byte[] decrypted = decrypt(cipher, recipient, sender, item, encrypted);

        Assertions.assertArrayEquals(plaintext(item), decrypted);
        Assertions.assertEquals(
          decrypted.length <= 512 ? JCSystem.CLEAR_ON_RESET : JCSystem.NOT_A_TRANSIENT_OBJECT,
          JCSystem.isTransient(decrypted)
        );
        Assertions.assertArrayEquals(original, encrypted);
      }
    }
  }

  @Test
  public void contextBindsTheCompleteIndexAndUnambiguousNullableMetadata() throws Exception {
    TestIdentity sender = new TestIdentity(1);
    TestIdentity recipient = new TestIdentity(2);
    ItemCipher cipher = new ItemCipher();
    SafeItem item = new SafeItem(INDEX, new byte[] { 1 }, new byte[] { 2, 3 }, bytes(32), true);
    byte[] encrypted = encryptOnHost(sender, recipient, item);

    for (int index = 0; index < INDEX.length; index++) {
      byte[] changed = INDEX.clone();
      changed[index] ^= 1;
      Assertions.assertThrows(CryptoException.class, () ->
        cipher.decrypt(
          recipient,
          changed,
          item.key,
          item.alias,
          sender.getPublicKey(),
          new TestData(encrypted)
        )
      );
    }

    Assertions.assertThrows(CryptoException.class, () ->
      cipher.decrypt(
        recipient,
        INDEX,
        new byte[] { 1, 2 },
        new byte[] { 3 },
        sender.getPublicKey(),
        new TestData(encrypted)
      )
    );

    for (int indexLength : new int[] { 0, 8, 9, 11 }) {
      Assertions.assertThrows(CryptoException.class, () ->
        cipher.decrypt(
          recipient,
          new byte[indexLength],
          item.key,
          item.alias,
          sender.getPublicKey(),
          new TestData(encrypted)
        )
      );
    }

    for (byte[] key : new byte[][] { null, new byte[0] }) {
      for (byte[] alias : new byte[][] { null, new byte[0] }) {
        SafeItem nullable = new SafeItem(INDEX, key, alias, bytes(32), false);
        byte[] envelope = encryptOnHost(sender, recipient, nullable);
        byte[] changedKey = key == null ? new byte[0] : null;
        byte[] changedAlias = alias == null ? new byte[0] : null;

        Assertions.assertThrows(CryptoException.class, () ->
          cipher.decrypt(
            recipient,
            INDEX,
            changedKey,
            alias,
            sender.getPublicKey(),
            new TestData(envelope)
          )
        );
        Assertions.assertThrows(CryptoException.class, () ->
          cipher.decrypt(
            recipient,
            INDEX,
            key,
            changedAlias,
            sender.getPublicKey(),
            new TestData(envelope)
          )
        );
        Assertions.assertArrayEquals(
          plaintext(nullable),
          decrypt(cipher, recipient, sender, nullable, envelope)
        );
      }
    }

    Assertions.assertArrayEquals(
      plaintext(item),
      decrypt(cipher, recipient, sender, item, encrypted)
    );
  }

  @Test
  public void rejectsMalformedContainersAndTamperingBeforeReturningPlaintext() throws Exception {
    TestIdentity sender = new TestIdentity(1);
    TestIdentity recipient = new TestIdentity(2);
    ItemCipher cipher = new ItemCipher();
    SafeItem item = item(bytes(32), true);
    byte[] encrypted = encryptOnHost(sender, recipient, item);

    for (int length = 0; length < 144; length++) {
      byte[] truncated = Arrays.copyOf(encrypted, length);
      Assertions.assertThrows(CryptoException.class, () ->
        decrypt(cipher, recipient, sender, item, truncated)
      );
    }

    // Version, HPKE encapsulation/key/tag, nonce and item ciphertext are all bound.
    for (int offset : new int[] { 0, 33, 65, 66, 97, 98, 113, 114, 125, 126, 127, 128, 159 }) {
      byte[] changed = encrypted.clone();
      changed[offset] ^= 1;
      Assertions.assertThrows(CryptoException.class, () ->
        decrypt(cipher, recipient, sender, item, changed)
      );
    }

    for (int index = encrypted.length - 16; index < encrypted.length; index++) {
      byte[] changed = encrypted.clone();
      changed[index] ^= 1;
      byte[] original = changed.clone();
      Assertions.assertThrows(CryptoException.class, () ->
        decrypt(cipher, recipient, sender, item, changed)
      );
      Assertions.assertArrayEquals(original, changed);
    }

    for (int length : new int[] { 144, encrypted.length - 1, encrypted.length + 1 }) {
      byte[] changed = Arrays.copyOf(encrypted, length);
      Assertions.assertThrows(CryptoException.class, () ->
        decrypt(cipher, recipient, sender, item, changed)
      );
    }

    Assertions.assertArrayEquals(
      plaintext(item),
      decrypt(cipher, recipient, sender, item, encrypted)
    );
  }

  @Test
  public void bindsExpectedSenderAndRecipient() throws Exception {
    TestIdentity sender = new TestIdentity(1);
    TestIdentity recipient = new TestIdentity(2);
    TestIdentity other = new TestIdentity(3);
    SafeItem item = item(bytes(32), true);
    byte[] encrypted = encryptOnHost(sender, recipient, item);
    ItemCipher cipher = new ItemCipher();

    Assertions.assertThrows(CryptoException.class, () ->
      decrypt(cipher, recipient, other, item, encrypted)
    );
    Assertions.assertThrows(CryptoException.class, () ->
      decrypt(new ItemCipher(), other, sender, item, encrypted)
    );
    Assertions.assertArrayEquals(
      plaintext(item),
      decrypt(cipher, recipient, sender, item, encrypted)
    );
  }

  @Test
  public void authenticatesPersistentPlaintextBeforeReturningIt() throws Exception {
    TestIdentity sender = new TestIdentity(1);
    TestIdentity recipient = new TestIdentity(2);
    ItemCipher cipher = new ItemCipher();
    SafeItem item = item(bytes(4096), true);
    byte[] encrypted = encryptOnHost(sender, recipient, item);
    byte[] changed = encrypted.clone();
    changed[changed.length - 1] ^= 1;

    CryptoException exception = Assertions.assertThrows(CryptoException.class, () ->
      decrypt(cipher, recipient, sender, item, changed)
    );
    Assertions.assertEquals(CryptoException.ILLEGAL_VALUE, exception.getReason());
    Assertions.assertArrayEquals(
      plaintext(item),
      decrypt(cipher, recipient, sender, item, encrypted)
    );
  }

  @Test
  public void repeatedExportsUseFreshKeysAndNonces() {
    TestIdentity identity = new TestIdentity(1);
    ItemCipher cipher = new ItemCipher();
    SafeItem item = item(bytes(32), true);
    byte[] first = cipher.encrypt(identity, item, identity.getPublicKey());
    byte[] firstKey = identity.lastKey.clone();
    byte[] second = cipher.encrypt(identity, item, identity.getPublicKey());

    Assertions.assertFalse(Arrays.equals(firstKey, identity.lastKey));
    Assertions.assertFalse(
      Arrays.equals(Arrays.copyOfRange(first, 1, 114), Arrays.copyOfRange(second, 1, 114))
    );
    Assertions.assertFalse(
      Arrays.equals(Arrays.copyOfRange(first, 114, 126), Arrays.copyOfRange(second, 114, 126))
    );
    Assertions.assertArrayEquals(plaintext(item), decrypt(cipher, identity, identity, item, first));
    Assertions.assertArrayEquals(
      plaintext(item),
      decrypt(cipher, identity, identity, item, second)
    );
  }

  @Test
  public void verifiesTheCompleteTagAgainOnEachOfThreeSuccessfulRounds() throws Exception {
    TestIdentity sender = new TestIdentity(1);
    TestIdentity recipient = new TestIdentity(2);
    ItemCipher cipher = new ItemCipher();
    SafeItem item = item(bytes(32), true);
    byte[] encrypted = encryptOnHost(sender, recipient, item);
    Field field = ItemCipher.class.getDeclaredField("tagValidation");
    field.setAccessible(true);
    LibSecurity.Condition original = (LibSecurity.Condition) field.get(cipher);

    for (int failedRound = 0; failedRound <= 3; failedRound++) {
      int failure = failedRound;
      int[] calls = { 0 };
      field.set(
        cipher,
        (LibSecurity.Condition) () -> {
          calls[0]++;
          boolean valid = original.check();

          return valid && calls[0] != failure;
        }
      );

      if (failure == 0) {
        Assertions.assertArrayEquals(
          plaintext(item),
          decrypt(cipher, recipient, sender, item, encrypted)
        );
        Assertions.assertEquals(3, calls[0]);
      } else {
        Assertions.assertThrows(CryptoException.class, () ->
          decrypt(cipher, recipient, sender, item, encrypted)
        );
        Assertions.assertEquals(failure, calls[0]);
      }
    }

    field.set(cipher, original);
    Assertions.assertArrayEquals(
      plaintext(item),
      decrypt(cipher, recipient, sender, item, encrypted)
    );
  }

  private static SafeItem item(byte[] data, boolean secret) {
    return new SafeItem(INDEX, KEY, ALIAS, data, secret);
  }

  private static byte[] plaintext(SafeItem item) {
    byte[] result = new byte[item.data.length + 2];
    Util.setShort(result, (short) 0, item.secret);
    System.arraycopy(item.data, 0, result, 2, item.data.length);

    return result;
  }

  private static byte[] decrypt(
    ItemCipher cipher,
    TestIdentity recipient,
    TestIdentity sender,
    SafeItem item,
    byte[] encrypted
  ) {
    return cipher.decrypt(
      recipient,
      item.index,
      item.key,
      item.alias,
      sender.getPublicKey(),
      new TestData(encrypted)
    );
  }

  private static byte[] encryptOnHost(TestIdentity sender, TestIdentity recipient, SafeItem item)
    throws Exception {
    byte[] communicationKey = bytes(32);
    byte[] context = context(item);
    byte[] nonce = bytes(12);
    byte[] encryptedKey = sender.encryptCommunicationKey(
      recipient.getPublicKey(),
      context,
      communicationKey
    );
    byte[] ciphertext = cryptOnHost(
      Cipher.ENCRYPT_MODE,
      communicationKey,
      context,
      nonce,
      plaintext(item)
    );
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    result.write(1);
    result.write(encryptedKey);
    result.write(nonce);
    result.write(ciphertext);

    return result.toByteArray();
  }

  /** Independent encoding, RFC 5869 HMAC and JCE AES-GCM, not the card helpers. */
  private static byte[] context(SafeItem item) throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    DataOutputStream output = new DataOutputStream(bytes);
    output.write("Monoid Item".getBytes(StandardCharsets.US_ASCII));
    output.writeByte(1);
    output.write(item.index);

    for (byte[] value : new byte[][] { item.key, item.alias }) {
      output.writeShort(value == null ? 0xFFFF : value.length);

      if (value != null) {
        output.write(value);
      }
    }

    return MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
  }

  private static byte[] cryptOnHost(
    int mode,
    byte[] key,
    byte[] context,
    byte[] nonce,
    byte[] input
  ) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
    byte[] prk = mac.doFinal(key);
    mac.init(new SecretKeySpec(prk, "HmacSHA256"));
    mac.update("Monoid Item Key".getBytes(StandardCharsets.US_ASCII));
    mac.update(context);
    byte[] encryptionKey = Arrays.copyOf(mac.doFinal(new byte[] { 1 }), 16);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(mode, new SecretKeySpec(encryptionKey, "AES"), new GCMParameterSpec(128, nonce));

    return cipher.doFinal(input);
  }

  private static byte[] bytes(int length) {
    byte[] result = new byte[length];

    for (int index = 0; index < length; index++) {
      result[index] = (byte) index;
    }

    return result;
  }

  /** Uses real HPKE while exposing only public fixtures to the independent payload oracle. */
  private static class TestIdentity implements SafeIdentityShareable {

    private final CommunicationCipher cipher;
    private final byte[] publicKey;
    private byte[] lastKey;
    private byte[] lastContext;

    public TestIdentity(int scalar) {
      X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
      publicKey = curve.getG().multiply(BigInteger.valueOf(scalar)).getEncoded(false);
      KeyPair identity = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
      ECPrivateKey privatePart = (ECPrivateKey) identity.getPrivate();
      ECPublicKey publicPart = (ECPublicKey) identity.getPublic();
      LibSECP256r1.initialize(privatePart);
      LibSECP256r1.initialize(publicPart);
      byte[] privateKey = new byte[32];
      privateKey[31] = (byte) scalar;
      privatePart.setS(privateKey, (short) 0, (short) privateKey.length);
      publicPart.setW(publicKey, (short) 0, (short) publicKey.length);
      cipher = new CommunicationCipher(identity);
    }

    @Override
    public byte[] getId() {
      return new byte[4];
    }

    @Override
    public byte[] getPublicKey() {
      return publicKey.clone();
    }

    @Override
    public byte[] encryptCommunicationKey(byte[] recipientPublicKey, byte[] context, byte[] key) {
      lastKey = key.clone();
      lastContext = context.clone();

      return cipher.encrypt(recipientPublicKey, context, key);
    }

    @Override
    public byte[] decryptCommunicationKey(
      byte[] senderPublicKey,
      byte[] context,
      byte[] encryptedKey
    ) {
      try {
        return cipher.decrypt(senderPublicKey, context, encryptedKey);
      } catch (IllegalArgumentException exception) {
        // jCardSim leaks its host curve decoder's exception for an invalid ECDH point.
        throw new CryptoException(CryptoException.ILLEGAL_VALUE);
      }
    }
  }
}
