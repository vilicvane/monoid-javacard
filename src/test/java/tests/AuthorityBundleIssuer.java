package tests;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Independent host RFC 9180 Auth sender for Authority enrollment fixtures. */
final class AuthorityBundleIssuer {

  private final KeyPair identity;

  AuthorityBundleIssuer() throws Exception {
    identity = generateKeyPair();
  }

  byte[] publicKey() {
    return encodePublicKey(identity);
  }

  byte[] installationParameters() {
    return concat(new byte[] { 2 }, publicKey());
  }

  byte[] issue(byte[] recipient, byte[] root, boolean allowPeerExtension) throws Exception {
    byte flags = (byte) (2 | (allowPeerExtension ? 1 : 0));
    byte[] header = concat(new byte[] { 1, flags, 0, 1 }, recipient);

    byte[] info = MessageDigest.getInstance("SHA-256").digest(
      concat(ascii("Monoid Authority Bundle"), header)
    );

    KeyPair ephemeral = generateKeyPair();
    byte[] enc = encodePublicKey(ephemeral);

    byte[] kemSuite = concat(ascii("KEM"), new byte[] { 0, 16 });
    byte[] suite = concat(ascii("HPKE"), new byte[] { 0, 16, 0, 1, 0, 1 });

    byte[] sharedSecret = expand(
      extract(
        new byte[0],
        kemSuite,
        "eae_prk",
        concat(agree(ephemeral, recipient), agree(identity, recipient))
      ),
      kemSuite,
      "shared_secret",
      concat(enc, recipient, publicKey()),
      32
    );

    byte[] scheduleContext = concat(
      new byte[] { 2 },
      extract(new byte[0], suite, "psk_id_hash", new byte[0]),
      extract(new byte[0], suite, "info_hash", info)
    );

    byte[] secret = extract(sharedSecret, suite, "secret", new byte[0]);
    byte[] key = expand(secret, suite, "key", scheduleContext, 16);
    byte[] nonce = expand(secret, suite, "base_nonce", scheduleContext, 12);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
      Cipher.ENCRYPT_MODE,
      new SecretKeySpec(key, "AES"),
      new GCMParameterSpec(128, nonce)
    );

    return concat(header, enc, cipher.doFinal(root));
  }

  private static KeyPair generateKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));

    return generator.generateKeyPair();
  }

  private static byte[] encodePublicKey(KeyPair pair) {
    ECPublicKey key = (ECPublicKey) pair.getPublic();

    byte[] encoded = new byte[65];
    encoded[0] = 4;

    BigInteger[] coordinates = { key.getW().getAffineX(), key.getW().getAffineY() };

    for (int index = 0; index < coordinates.length; index++) {
      byte[] coordinate = coordinates[index].toByteArray();
      int length = Math.min(32, coordinate.length);

      System.arraycopy(
        coordinate,
        coordinate.length - length,
        encoded,
        1 + index * 32 + 32 - length,
        length
      );
    }

    return encoded;
  }

  private static byte[] agree(KeyPair pair, byte[] recipient) throws Exception {
    ECPoint point = new ECPoint(
      new BigInteger(1, Arrays.copyOfRange(recipient, 1, 33)),
      new BigInteger(1, Arrays.copyOfRange(recipient, 33, 65))
    );
    ECPublicKeySpec spec = new ECPublicKeySpec(point, ((ECPublicKey) pair.getPublic()).getParams());

    KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
    agreement.init(pair.getPrivate());
    agreement.doPhase(KeyFactory.getInstance("EC").generatePublic(spec), true);

    return agreement.generateSecret();
  }

  private static byte[] extract(byte[] salt, byte[] suite, String label, byte[] input)
    throws Exception {
    return hmac(
      salt.length == 0 ? new byte[32] : salt,
      concat(ascii("HPKE-v1"), suite, ascii(label), input)
    );
  }

  private static byte[] expand(byte[] prk, byte[] suite, String label, byte[] info, int length)
    throws Exception {
    return Arrays.copyOf(
      hmac(
        prk,
        concat(
          new byte[] { 0, (byte) length },
          ascii("HPKE-v1"),
          suite,
          ascii(label),
          info,
          new byte[] { 1 }
        )
      ),
      length
    );
  }

  private static byte[] hmac(byte[] key, byte[] input) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));

    return mac.doFinal(input);
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    for (byte[] part : parts) {
      output.write(part, 0, part.length);
    }

    return output.toByteArray();
  }
}
