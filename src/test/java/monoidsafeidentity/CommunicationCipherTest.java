package monoidsafeidentity;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CommunicationCipherTest {

  private static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256r1");
  private static final byte[] COMMUNICATION_KEY = Hex.decode(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  );
  private static final byte[] CONTEXT = "Monoid card communication".getBytes(
    StandardCharsets.US_ASCII
  );

  // RFC 9180, appendix A.3.3: Auth / DHKEM(P-256, HKDF-SHA256) / AES-128-GCM.
  private static final byte[] RECIPIENT_PRIVATE_KEY = Hex.decode(
    "d929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e"
  );
  private static final byte[] SENDER_PRIVATE_KEY = Hex.decode(
    "1120ac99fb1fccc1e8230502d245719d1b217fe20505c7648795139d177f0de9"
  );
  private static final byte[] SENDER_PUBLIC_KEY = Hex.decode(
    "04a817a0902bf28e036d66add5d544cc3a0457eab150f104285df1e293b5c10eef8651213e43d9cd9086c80b309df22cf37609f58c1127f7607e85f210b2804f73"
  );
  private static final byte[] RECIPIENT_PUBLIC_KEY = Hex.decode(
    "04423e363e1cd54ce7b7573110ac121399acbc9ed815fae03b72ffbd4c18b01836835c5a09513f28fc971b7266cfde2e96afe84bb0f266920e82c4f53b36e1a78d"
  );

  @Test
  public void unsignedComparisonRespectsByteBoundariesOffsetsAndLaterBytes() throws Exception {
    Method compare = CommunicationCipher.class.getDeclaredMethod(
      "compareUnsigned",
      byte[].class,
      short.class,
      byte[].class,
      short.class,
      short.class
    );
    compare.setAccessible(true);
    String[] values = { "0000", "00ff", "7f00", "7fff", "8000", "80ff", "ff00", "ffff" };

    for (int left = 0; left < values.length; left++) {
      for (int right = 0; right < values.length; right++) {
        byte[] a = Hex.decode("ff" + values[left] + "00");
        byte[] b = Hex.decode("0000" + values[right] + "ff");
        int result = (Byte) compare.invoke(null, a, (short) 1, b, (short) 2, (short) 2);

        Assertions.assertEquals(
          Integer.signum(left - right),
          Integer.signum(result),
          values[left] + " compared with " + values[right]
        );
      }
    }
  }

  @Test
  public void lowAndHighCoordinatePublicKeysSupportBothCommunicationDirections() {
    byte[] lowPrivateKey = new byte[32];
    byte[] highPrivateKey = new byte[32];
    lowPrivateKey[31] = 1;
    highPrivateKey[31] = 4;
    KeyPair lowIdentity = identity(lowPrivateKey);
    KeyPair highIdentity = identity(highPrivateKey);
    byte[] lowPublicKey = new byte[65];
    byte[] highPublicKey = new byte[65];
    ((ECPublicKey) lowIdentity.getPublic()).getW(lowPublicKey, (short) 0);
    ((ECPublicKey) highIdentity.getPublic()).getW(highPublicKey, (short) 0);

    for (int offset : new int[] { 1, 33 }) {
      Assertions.assertTrue((lowPublicKey[offset] & 0x80) == 0);
      Assertions.assertTrue((highPublicKey[offset] & 0x80) != 0);
    }

    CommunicationCipher low = new CommunicationCipher(lowIdentity);
    CommunicationCipher high = new CommunicationCipher(highIdentity);
    byte[] encryptedKey = low.encrypt(highPublicKey, CONTEXT, COMMUNICATION_KEY);
    Assertions.assertArrayEquals(
      COMMUNICATION_KEY,
      high.decrypt(lowPublicKey, CONTEXT, encryptedKey)
    );

    encryptedKey = high.encrypt(lowPublicKey, CONTEXT, COMMUNICATION_KEY);
    Assertions.assertArrayEquals(
      COMMUNICATION_KEY,
      low.decrypt(highPublicKey, CONTEXT, encryptedKey)
    );
  }

  @Test
  public void decryptUsesRFC9180AuthenticationKeySchedule() throws Exception {
    byte[] enc = Hex.decode(
      "042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454"
    );
    byte[] info = Hex.decode("4f6465206f6e2061204772656369616e2055726e");
    byte[] key = Hex.decode("19aa8472b3fdc530392b0e54ca17c0f5");
    byte[] nonce = Hex.decode("b390052d26b67a5b8a8fcaa4");
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
      Cipher.ENCRYPT_MODE,
      new SecretKeySpec(key, "AES"),
      new GCMParameterSpec(128, nonce)
    );
    // Keep the RFC key schedule, with this interface's 32-byte plaintext and empty AAD.
    byte[] encryptedKey = concat(enc, cipher.doFinal(COMMUNICATION_KEY));
    CommunicationCipher recipient = new CommunicationCipher(identity(RECIPIENT_PRIVATE_KEY));

    Assertions.assertArrayEquals(
      COMMUNICATION_KEY,
      recipient.decrypt(SENDER_PUBLIC_KEY, info, encryptedKey)
    );
  }

  @Test
  public void freshEncryptionsMatchIndependentHostDecryption() throws Exception {
    CommunicationCipher sender = new CommunicationCipher(identity(SENDER_PRIVATE_KEY));
    CommunicationCipher recipient = new CommunicationCipher(identity(RECIPIENT_PRIVATE_KEY));
    byte[] first = sender.encrypt(RECIPIENT_PUBLIC_KEY, CONTEXT, COMMUNICATION_KEY);
    byte[] second = sender.encrypt(RECIPIENT_PUBLIC_KEY, CONTEXT, COMMUNICATION_KEY);

    Assertions.assertEquals(113, first.length);
    Assertions.assertFalse(Arrays.equals(first, second));

    for (byte[] encryptedKey : new byte[][] { first, second }) {
      Assertions.assertArrayEquals(COMMUNICATION_KEY, decryptOnHost(encryptedKey));
      Assertions.assertArrayEquals(
        COMMUNICATION_KEY,
        recipient.decrypt(SENDER_PUBLIC_KEY, CONTEXT, encryptedKey)
      );
    }
  }

  @Test
  public void selfEncryptionKeepsTheStableIdentity() {
    KeyPair identity = identity(SENDER_PRIVATE_KEY);
    CommunicationCipher cipher = new CommunicationCipher(identity);

    for (int pass = 0; pass < 2; pass++) {
      byte[] encryptedKey = cipher.encrypt(SENDER_PUBLIC_KEY, CONTEXT, COMMUNICATION_KEY);

      Assertions.assertArrayEquals(
        COMMUNICATION_KEY,
        cipher.decrypt(SENDER_PUBLIC_KEY, CONTEXT, encryptedKey)
      );
    }

    byte[] publicKey = new byte[65];
    ((ECPublicKey) identity.getPublic()).getW(publicKey, (short) 0);
    Assertions.assertArrayEquals(SENDER_PUBLIC_KEY, publicKey);
  }

  @Test
  public void authenticationBindsSenderRecipientContextAndCiphertext() {
    CommunicationCipher sender = new CommunicationCipher(identity(SENDER_PRIVATE_KEY));
    CommunicationCipher recipient = new CommunicationCipher(identity(RECIPIENT_PRIVATE_KEY));
    byte[] encryptedKey = sender.encrypt(RECIPIENT_PUBLIC_KEY, CONTEXT, COMMUNICATION_KEY);

    Assertions.assertThrows(RuntimeException.class, () ->
      recipient.decrypt(RECIPIENT_PUBLIC_KEY, CONTEXT, encryptedKey)
    );
    Assertions.assertThrows(RuntimeException.class, () ->
      sender.decrypt(SENDER_PUBLIC_KEY, CONTEXT, encryptedKey)
    );
    Assertions.assertThrows(RuntimeException.class, () ->
      recipient.decrypt(SENDER_PUBLIC_KEY, new byte[0], encryptedKey)
    );

    for (int offset : new int[] { 65, 96, 97, 112 }) {
      byte[] corrupted = encryptedKey.clone();
      corrupted[offset] ^= 1;

      Assertions.assertThrows(RuntimeException.class, () ->
        recipient.decrypt(SENDER_PUBLIC_KEY, CONTEXT, corrupted)
      );
    }

    Assertions.assertArrayEquals(
      COMMUNICATION_KEY,
      recipient.decrypt(SENDER_PUBLIC_KEY, CONTEXT, encryptedKey)
    );
  }

  @Test
  public void tagVerificationRunsFreshChecksAndFailsConservativelyInEachRound() throws Exception {
    CommunicationCipher sender = new CommunicationCipher(identity(SENDER_PRIVATE_KEY));
    CommunicationCipher recipient = new CommunicationCipher(identity(RECIPIENT_PRIVATE_KEY));
    byte[] encryptedKey = sender.encrypt(RECIPIENT_PUBLIC_KEY, CONTEXT, COMMUNICATION_KEY);
    Field validation = CommunicationCipher.class.getDeclaredField("tagValidation");
    validation.setAccessible(true);
    LibSecurity.Condition original = (LibSecurity.Condition) validation.get(recipient);

    try {
      for (int failureRound = 1; failureRound <= 3; failureRound++) {
        int failure = failureRound;
        int[] calls = { 0 };
        validation.set(
          recipient,
          (LibSecurity.Condition) () -> {
            calls[0]++;
            return original.check() && calls[0] != failure;
          }
        );

        Assertions.assertThrows(RuntimeException.class, () ->
          recipient.decrypt(SENDER_PUBLIC_KEY, CONTEXT, encryptedKey)
        );
        Assertions.assertEquals(failureRound, calls[0]);
      }

      int[] calls = { 0 };
      validation.set(
        recipient,
        (LibSecurity.Condition) () -> {
          calls[0]++;
          return original.check();
        }
      );

      for (int pass = 1; pass <= 2; pass++) {
        Assertions.assertArrayEquals(
          COMMUNICATION_KEY,
          recipient.decrypt(SENDER_PUBLIC_KEY, CONTEXT, encryptedKey)
        );
        Assertions.assertEquals(3 * pass, calls[0]);
      }
    } finally {
      validation.set(recipient, original);
    }
  }

  @Test
  public void rejectsNonCanonicalAndOffCurvePublicKeys() {
    CommunicationCipher sender = new CommunicationCipher(identity(SENDER_PRIVATE_KEY));
    CommunicationCipher recipient = new CommunicationCipher(identity(RECIPIENT_PRIVATE_KEY));
    byte[] encryptedKey = sender.encrypt(RECIPIENT_PUBLIC_KEY, CONTEXT, COMMUNICATION_KEY);
    byte[] infinity = new byte[65];
    byte[] offCurve = new byte[65];
    offCurve[0] = 4;
    byte[] outOfRangeX = RECIPIENT_PUBLIC_KEY.clone();
    System.arraycopy(LibSECP256r1.FP, 0, outOfRangeX, 1, 32);
    byte[] outOfRangeY = RECIPIENT_PUBLIC_KEY.clone();
    System.arraycopy(LibSECP256r1.FP, 0, outOfRangeY, 33, 32);
    byte[] compressed = CURVE.getG().getEncoded(true);

    for (byte[] publicKey : new byte[][] {
      infinity,
      offCurve,
      outOfRangeX,
      outOfRangeY,
      compressed,
    }) {
      Assertions.assertThrows(RuntimeException.class, () ->
        sender.encrypt(publicKey, CONTEXT, COMMUNICATION_KEY)
      );
      Assertions.assertThrows(RuntimeException.class, () ->
        recipient.decrypt(publicKey, CONTEXT, encryptedKey)
      );
    }

    System.arraycopy(offCurve, 0, encryptedKey, 0, 65);
    Assertions.assertThrows(RuntimeException.class, () ->
      recipient.decrypt(SENDER_PUBLIC_KEY, CONTEXT, encryptedKey)
    );
  }

  @Test
  public void rejectsUnsupportedKeyAndEnvelopeLengths() {
    CommunicationCipher sender = new CommunicationCipher(identity(SENDER_PRIVATE_KEY));

    for (int length : new int[] { 0, 16, 31, 33 }) {
      Assertions.assertThrows(RuntimeException.class, () ->
        sender.encrypt(RECIPIENT_PUBLIC_KEY, CONTEXT, new byte[length])
      );
    }

    for (int length : new int[] { 0, 65, 112, 114 }) {
      Assertions.assertThrows(RuntimeException.class, () ->
        sender.decrypt(RECIPIENT_PUBLIC_KEY, CONTEXT, new byte[length])
      );
    }
  }

  private static KeyPair identity(byte[] privateKey) {
    KeyPair identity = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
    ECPrivateKey privatePart = (ECPrivateKey) identity.getPrivate();
    ECPublicKey publicPart = (ECPublicKey) identity.getPublic();
    LibSECP256r1.initialize(privatePart);
    LibSECP256r1.initialize(publicPart);
    privatePart.setS(privateKey, (short) 0, (short) privateKey.length);
    byte[] publicKey = CURVE.getG().multiply(new BigInteger(1, privateKey)).getEncoded(false);
    publicPart.setW(publicKey, (short) 0, (short) publicKey.length);

    return identity;
  }

  /** Independent JCE HMAC/GCM and host curve implementation of RFC 9180 AuthDecap. */
  private static byte[] decryptOnHost(byte[] encryptedKey) throws Exception {
    byte[] enc = Arrays.copyOf(encryptedKey, 65);
    BigInteger privateKey = new BigInteger(1, RECIPIENT_PRIVATE_KEY);
    byte[] ephemeralDH = CURVE.getCurve()
      .decodePoint(enc)
      .multiply(privateKey)
      .normalize()
      .getAffineXCoord()
      .getEncoded();
    byte[] staticDH = CURVE.getCurve()
      .decodePoint(SENDER_PUBLIC_KEY)
      .multiply(privateKey)
      .normalize()
      .getAffineXCoord()
      .getEncoded();
    byte[] kemSuite = concat("KEM".getBytes(StandardCharsets.US_ASCII), new byte[] { 0, 16 });
    byte[] suite = concat(
      "HPKE".getBytes(StandardCharsets.US_ASCII),
      new byte[] { 0, 16, 0, 1, 0, 1 }
    );
    byte[] sharedSecret = expand(
      extract(new byte[0], kemSuite, "eae_prk", concat(ephemeralDH, staticDH)),
      kemSuite,
      "shared_secret",
      concat(enc, RECIPIENT_PUBLIC_KEY, SENDER_PUBLIC_KEY),
      32
    );
    byte[] scheduleContext = concat(
      new byte[] { 2 },
      extract(new byte[0], suite, "psk_id_hash", new byte[0]),
      extract(new byte[0], suite, "info_hash", CONTEXT)
    );
    byte[] secret = extract(sharedSecret, suite, "secret", new byte[0]);
    byte[] key = expand(secret, suite, "key", scheduleContext, 16);
    byte[] nonce = expand(secret, suite, "base_nonce", scheduleContext, 12);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
      Cipher.DECRYPT_MODE,
      new SecretKeySpec(key, "AES"),
      new GCMParameterSpec(128, nonce)
    );

    return cipher.doFinal(encryptedKey, 65, 48);
  }

  private static byte[] extract(byte[] salt, byte[] suite, String label, byte[] input)
    throws Exception {
    return hmac(
      salt.length == 0 ? new byte[32] : salt,
      concat(
        "HPKE-v1".getBytes(StandardCharsets.US_ASCII),
        suite,
        label.getBytes(StandardCharsets.US_ASCII),
        input
      )
    );
  }

  private static byte[] expand(byte[] prk, byte[] suite, String label, byte[] info, int length)
    throws Exception {
    return Arrays.copyOf(
      hmac(
        prk,
        concat(
          new byte[] { 0, (byte) length },
          "HPKE-v1".getBytes(StandardCharsets.US_ASCII),
          suite,
          label.getBytes(StandardCharsets.US_ASCII),
          info,
          new byte[] { 1 }
        )
      ),
      length
    );
  }

  private static byte[] hmac(byte[] key, byte[] data) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));

    return mac.doFinal(data);
  }

  private static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream result = new ByteArrayOutputStream();

    for (byte[] part : parts) {
      result.write(part, 0, part.length);
    }

    return result.toByteArray();
  }
}
