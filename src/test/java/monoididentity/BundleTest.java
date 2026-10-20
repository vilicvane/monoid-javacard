package monoididentity;

import static tests.AppletTest.aidBytes;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.IdentityCallerApplet.Data;

public class BundleTest {

  private static final AID CALLER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );

  private static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256r1");
  private static final byte[] INDEX = { 3, 0, 1, 2, 3, 4, 5, 6, 7, 8 };
  private static final byte[] KEY = { 1, 2, 3 };
  private static final byte[] ALIAS = "bundle item".getBytes(StandardCharsets.UTF_8);

  private final AESGcmCipher sharedCipher = new AESGcmCipher();

  @Test
  public void enrollmentMatchesIndependentHpkeAndInstallsTheSamePrivateKey() throws Exception {
    CommunicationCipher sender = communication(1);
    CommunicationCipher receiver = communication(2);
    byte[] inputMembers = concat(publicKey(2), publicKey(1));
    Bundle created = Bundle.create(inputMembers, publicKey(1), sender);
    byte[] envelope = created.encryptPackets(inputMembers, publicKey(1), sender);
    byte[] members = Arrays.copyOfRange(envelope, 3, 133);
    byte[] expectedMembers = compare(publicKey(1), publicKey(2)) < 0
      ? concat(publicKey(1), publicKey(2))
      : concat(publicKey(2), publicKey(1));

    Assertions.assertEquals(246, envelope.length);
    Assertions.assertEquals(1, envelope[0]);
    Assertions.assertEquals(2, envelope[2]);
    Assertions.assertArrayEquals(expectedMembers, members);
    Assertions.assertArrayEquals(created.key, openEnrollment(envelope, 1, 2));
    Assertions.assertArrayEquals(sha256(created.key), created.hash);
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(created.key));

    Bundle imported = Bundle.decrypt(publicKey(1), publicKey(2), envelope, receiver);
    Assertions.assertTrue(created.matches(imported));
    Assertions.assertNotSame(created.key, imported.key);
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(imported.key));
    Assertions.assertArrayEquals(created.hash, imported.hash);
    Assertions.assertArrayEquals(
      created.key,
      openEnrollment(imported.encryptPackets(inputMembers, publicKey(2), receiver), 2, 1)
    );
  }

  @Test
  public void enrollmentRejectsMissingDuplicateAndChangedMembers() {
    CommunicationCipher sender = communication(1);
    byte[] members = concat(publicKey(1), publicKey(2));
    Bundle bundle = Bundle.create(members, publicKey(1), sender);
    byte[] envelope = bundle.encryptPackets(members, publicKey(1), sender);

    Assertions.assertThrows(RuntimeException.class, () ->
      Bundle.create(publicKey(1), publicKey(1), sender)
    );
    Assertions.assertThrows(RuntimeException.class, () ->
      Bundle.create(concat(publicKey(1), publicKey(1)), publicKey(1), sender)
    );
    Assertions.assertThrows(RuntimeException.class, () ->
      Bundle.create(members, publicKey(3), sender)
    );
    Assertions.assertThrows(RuntimeException.class, () ->
      Bundle.decrypt(publicKey(3), publicKey(2), envelope, communication(2))
    );
    Assertions.assertThrows(RuntimeException.class, () ->
      Bundle.decrypt(publicKey(1), publicKey(3), envelope, communication(3))
    );

    for (int offset : new int[] { 0, 2, 20, 80, 160, 245 }) {
      byte[] changed = envelope.clone();
      changed[offset] ^= 1;
      Assertions.assertThrows(RuntimeException.class, () ->
        Bundle.decrypt(publicKey(1), publicKey(2), changed, communication(2))
      );
    }

    byte[] reordered = envelope.clone();
    System.arraycopy(envelope, 3, reordered, 68, 65);
    System.arraycopy(envelope, 68, reordered, 3, 65);
    Assertions.assertThrows(RuntimeException.class, () ->
      Bundle.decrypt(publicKey(1), publicKey(2), reordered, communication(2))
    );
    Assertions.assertFalse(bundle.matches(Bundle.create(members, publicKey(1), sender)));
  }

  @Test
  public void allEnrollmentPacketsPreserveInputOrderWithoutTransientOutputArrays()
    throws Exception {
    CommunicationCipher sender = communication(1);
    byte[] members = concat(publicKey(3), publicKey(1), publicKey(2));
    Bundle bundle = Bundle.create(members, publicKey(1), sender);
    byte[] packets = bundle.encryptPackets(members, publicKey(1), sender);
    Assertions.assertEquals(622, packets.length);
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(packets));
    Assertions.assertArrayEquals(
      bundle.key,
      openEnrollment(Arrays.copyOfRange(packets, 0, 311), 1, 3)
    );
    Assertions.assertArrayEquals(
      bundle.key,
      openEnrollment(Arrays.copyOfRange(packets, 311, 622), 1, 2)
    );
  }

  @Test
  public void bundleItemsMatchIndependentHkdfAndGcmInBothDirections() throws Exception {
    CommunicationCipher sender = communication(1);
    CommunicationCipher receiver = communication(2);
    byte[] members = concat(publicKey(1), publicKey(2));
    Bundle bundle = Bundle.create(members, publicKey(1), sender);
    Bundle imported = Bundle.decrypt(
      publicKey(1),
      publicKey(2),
      bundle.encryptPackets(members, publicKey(1), sender),
      receiver
    );
    ItemCipher cipher = new ItemCipher(sharedCipher);

    for (short secret : new short[] { Constants.SAFE_FALSE, Constants.SAFE_TRUE }) {
      for (int length : new int[] { 0, 1, 14, 15, 16, 128, 1024, 4096 }) {
        byte[] data = bytes(length);
        byte[] encrypted = cipher.encrypt(
          sender,
          bundle,
          CALLER_AID,
          INDEX,
          KEY,
          ALIAS,
          secret,
          publicKey(3),
          new Data(data)
        );
        byte[] plaintext = concat(new byte[] { (byte) (secret >> 8), (byte) secret }, data);
        Assertions.assertEquals(length + 95, encrypted.length);
        Assertions.assertEquals(2, encrypted[0]);
        Assertions.assertArrayEquals(bundle.hash, Arrays.copyOfRange(encrypted, 1, 33));
        Assertions.assertArrayEquals(
          plaintext,
          bundleCrypt(
            Cipher.DECRYPT_MODE,
            bundle.key,
            encrypted,
            Arrays.copyOfRange(encrypted, 77, encrypted.length)
          )
        );
        Assertions.assertArrayEquals(
          plaintext,
          cipher.decrypt(
            receiver,
            imported,
            CALLER_AID,
            INDEX,
            KEY,
            ALIAS,
            null,
            new Data(encrypted)
          )
        );

        byte[] hostEnvelope = encrypted.clone();
        byte[] ciphertext = bundleCrypt(Cipher.ENCRYPT_MODE, bundle.key, hostEnvelope, plaintext);
        System.arraycopy(ciphertext, 0, hostEnvelope, 77, ciphertext.length);
        Assertions.assertArrayEquals(
          plaintext,
          cipher.decrypt(
            receiver,
            imported,
            CALLER_AID,
            INDEX,
            KEY,
            ALIAS,
            null,
            new Data(hostEnvelope)
          )
        );
      }
    }
  }

  @Test
  public void bundleItemsBindMetadataKeyAndEnvelopeAndRequireMembership() {
    CommunicationCipher sender = communication(1);
    Bundle bundle = Bundle.create(concat(publicKey(1), publicKey(2)), publicKey(1), sender);
    Bundle different = Bundle.create(concat(publicKey(1), publicKey(2)), publicKey(1), sender);
    ItemCipher cipher = new ItemCipher(sharedCipher);
    byte[] encrypted = cipher.encrypt(
      sender,
      bundle,
      CALLER_AID,
      INDEX,
      KEY,
      ALIAS,
      Constants.SAFE_TRUE,
      null,
      new Data(bytes(32))
    );

    Assertions.assertThrows(RuntimeException.class, () ->
      cipher.decrypt(sender, null, CALLER_AID, INDEX, KEY, ALIAS, null, new Data(encrypted))
    );
    Assertions.assertThrows(RuntimeException.class, () ->
      cipher.decrypt(sender, different, CALLER_AID, INDEX, KEY, ALIAS, null, new Data(encrypted))
    );
    Assertions.assertThrows(RuntimeException.class, () ->
      cipher.decrypt(
        sender,
        bundle,
        CALLER_AID,
        new byte[10],
        KEY,
        ALIAS,
        null,
        new Data(encrypted)
      )
    );
    Assertions.assertThrows(RuntimeException.class, () ->
      cipher.decrypt(
        sender,
        bundle,
        CALLER_AID,
        INDEX,
        new byte[0],
        ALIAS,
        null,
        new Data(encrypted)
      )
    );
    Assertions.assertThrows(RuntimeException.class, () ->
      cipher.decrypt(sender, bundle, CALLER_AID, INDEX, KEY, null, null, new Data(encrypted))
    );

    for (int offset : new int[] { 0, 1, 33, 65, 77, encrypted.length - 1 }) {
      byte[] changed = encrypted.clone();
      changed[offset] ^= 1;
      Assertions.assertThrows(RuntimeException.class, () ->
        cipher.decrypt(sender, bundle, CALLER_AID, INDEX, KEY, ALIAS, null, new Data(changed))
      );
    }
  }

  @Test
  public void bundleItemsAreIsolatedByTheFullCallerAIDAndItsLength() {
    CommunicationCipher sender = communication(1);
    Bundle bundle = Bundle.create(concat(publicKey(1), publicKey(2)), publicKey(1), sender);
    ItemCipher cipher = new ItemCipher(sharedCipher);
    byte[] data = bytes(32);
    byte[] encrypted = cipher.encrypt(
      sender,
      bundle,
      CALLER_AID,
      INDEX,
      KEY,
      ALIAS,
      Constants.SAFE_TRUE,
      null,
      new Data(data)
    );
    byte[] caller = aidBytes(CALLER_AID);
    byte[] changed = caller.clone();
    changed[changed.length - 1] ^= 1;
    byte[] extended = Arrays.copyOf(caller, caller.length + 1);

    for (byte[] other : new byte[][] { changed, extended }) {
      AID otherCaller = new AID(other, (short) 0, (byte) other.length);
      Assertions.assertThrows(CryptoException.class, () ->
        cipher.decrypt(sender, bundle, otherCaller, INDEX, KEY, ALIAS, null, new Data(encrypted))
      );
    }

    Assertions.assertArrayEquals(
      concat(new byte[] { 0x5A, (byte) 0xFE }, data),
      cipher.decrypt(
        sender,
        bundle,
        new AID(caller, (short) 0, (byte) caller.length),
        INDEX,
        KEY,
        ALIAS,
        null,
        new Data(encrypted)
      )
    );
  }

  @Test
  public void bundledIdentityStillReceivesOrdinaryTransfersButCannotUnwrapEnrollmentAsData() {
    CommunicationCipher sender = communication(1);
    CommunicationCipher receiver = communication(2);
    byte[] members = concat(publicKey(1), publicKey(2));
    Bundle bundle = Bundle.create(members, publicKey(1), sender);
    ItemCipher cipher = new ItemCipher(sharedCipher);
    byte[] encrypted = cipher.encrypt(
      sender,
      null,
      CALLER_AID,
      INDEX,
      KEY,
      ALIAS,
      Constants.SAFE_TRUE,
      publicKey(2),
      new Data(bytes(32))
    );
    Assertions.assertArrayEquals(
      concat(new byte[] { 0x5A, (byte) 0xFE }, bytes(32)),
      cipher.decrypt(
        receiver,
        bundle,
        CALLER_AID,
        INDEX,
        KEY,
        ALIAS,
        publicKey(1),
        new Data(encrypted)
      )
    );

    byte[] enrollment = bundle.encryptPackets(members, publicKey(1), sender);
    byte[] forgedItem = encrypted.clone();
    System.arraycopy(enrollment, 133, forgedItem, 1, 113);
    Assertions.assertThrows(RuntimeException.class, () ->
      cipher.decrypt(
        receiver,
        bundle,
        CALLER_AID,
        INDEX,
        KEY,
        ALIAS,
        publicKey(1),
        new Data(forgedItem)
      )
    );

    Bundle imported = Bundle.decrypt(publicKey(1), publicKey(2), enrollment, receiver);
    byte[] bundled = cipher.encrypt(
      receiver,
      imported,
      CALLER_AID,
      INDEX,
      KEY,
      ALIAS,
      Constants.SAFE_TRUE,
      null,
      new Data(bytes(32))
    );
    Assertions.assertArrayEquals(
      concat(new byte[] { 0x5A, (byte) 0xFE }, bytes(32)),
      cipher.decrypt(sender, bundle, CALLER_AID, INDEX, KEY, ALIAS, null, new Data(bundled))
    );
    Assertions.assertArrayEquals(
      concat(new byte[] { 0x5A, (byte) 0xFE }, bytes(32)),
      cipher.decrypt(
        receiver,
        imported,
        CALLER_AID,
        INDEX,
        KEY,
        ALIAS,
        publicKey(1),
        new Data(encrypted)
      )
    );
  }

  @Test
  public void sourceCallbacksCannotChangeTheMetadataOrRecipientOfAnOperation() {
    CommunicationCipher sender = communication(1);
    CommunicationCipher receiver = communication(2);
    ItemCipher cipher = new ItemCipher(sharedCipher);
    byte[] index = INDEX.clone();
    byte[] key = KEY.clone();
    byte[] alias = ALIAS.clone();
    byte[] recipient = publicKey(2);
    Data source = new Data(bytes(32)) {
      @Override
      public short getLength() {
        Arrays.fill(index, (byte) 0);
        Arrays.fill(key, (byte) 0);
        Arrays.fill(alias, (byte) 0);
        Arrays.fill(recipient, (byte) 0);
        return super.getLength();
      }
    };
    byte[] encrypted = cipher.encrypt(
      sender,
      null,
      CALLER_AID,
      index,
      key,
      alias,
      Constants.SAFE_TRUE,
      recipient,
      source
    );
    Assertions.assertArrayEquals(
      concat(new byte[] { 0x5A, (byte) 0xFE }, bytes(32)),
      cipher.decrypt(
        receiver,
        null,
        CALLER_AID,
        INDEX,
        KEY,
        ALIAS,
        publicKey(1),
        new Data(encrypted)
      )
    );
  }

  private byte[] bundleCrypt(int mode, byte[] key, byte[] envelope, byte[] input) throws Exception {
    byte[] salt = Arrays.copyOfRange(envelope, 33, 65);
    byte[] caller = aidBytes(CALLER_AID);
    byte[] callerKey = hmac(
      key,
      concat(ascii("Monoid Bundle Caller Key"), new byte[] { (byte) caller.length }, caller)
    );
    byte[] prk = hmac(salt, callerKey);
    byte[] encryptionKey = Arrays.copyOf(
      hmac(prk, concat(ascii("Monoid Bundle Item Key"), metadataContext(), new byte[] { 1 })),
      16
    );
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
      mode,
      new SecretKeySpec(encryptionKey, "AES"),
      new GCMParameterSpec(128, Arrays.copyOfRange(envelope, 65, 77))
    );
    return cipher.doFinal(input);
  }

  private byte[] metadataContext() throws Exception {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(buffer);
    out.write(ascii("Monoid Item"));
    out.writeByte(2);
    byte[] caller = aidBytes(CALLER_AID);
    out.writeByte(caller.length);
    out.write(caller);
    out.write(INDEX);
    out.writeShort(KEY.length);
    out.write(KEY);
    out.writeShort(ALIAS.length);
    out.write(ALIAS);
    return sha256(buffer.toByteArray());
  }

  private byte[] openEnrollment(byte[] envelope, int sender, int receiver) throws Exception {
    byte[] members = Arrays.copyOfRange(envelope, 3, envelope.length - 113);
    byte[] encrypted = Arrays.copyOfRange(envelope, envelope.length - 113, envelope.length);
    byte[] enc = Arrays.copyOf(encrypted, 65);
    byte[] dh = concat(
      CURVE.getCurve()
        .decodePoint(enc)
        .multiply(BigInteger.valueOf(receiver))
        .normalize()
        .getAffineXCoord()
        .getEncoded(),
      CURVE.getCurve()
        .decodePoint(publicKey(sender))
        .multiply(BigInteger.valueOf(receiver))
        .normalize()
        .getAffineXCoord()
        .getEncoded()
    );
    byte[] kemSuite = { 'K', 'E', 'M', 0, 0x10 };
    byte[] suite = { 'H', 'P', 'K', 'E', 0, 0x10, 0, 1, 0, 1 };
    byte[] prk = extract(new byte[0], kemSuite, "eae_prk", dh);
    byte[] shared = expand(
      prk,
      kemSuite,
      "shared_secret",
      concat(enc, publicKey(receiver), publicKey(sender)),
      32
    );
    byte[] info = sha256(concat(ascii("Monoid Bundle Enrollment"), new byte[] { 1 }, members));
    byte[] context = concat(
      new byte[] { 2 },
      extract(new byte[0], suite, "psk_id_hash", new byte[0]),
      extract(new byte[0], suite, "info_hash", info)
    );
    byte[] secret = extract(shared, suite, "secret", new byte[0]);
    byte[] key = expand(secret, suite, "key", context, 16);
    byte[] nonce = expand(secret, suite, "base_nonce", context, 12);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
      Cipher.DECRYPT_MODE,
      new SecretKeySpec(key, "AES"),
      new GCMParameterSpec(128, nonce)
    );
    return cipher.doFinal(Arrays.copyOfRange(encrypted, 65, 113));
  }

  private byte[] extract(byte[] salt, byte[] suite, String label, byte[] input) throws Exception {
    return hmac(salt, concat(ascii("HPKE-v1"), suite, ascii(label), input));
  }

  private byte[] expand(byte[] key, byte[] suite, String label, byte[] info, int length)
    throws Exception {
    return Arrays.copyOf(
      hmac(
        key,
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

  private byte[] hmac(byte[] key, byte[] data) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key.length == 0 ? new byte[32] : key, "HmacSHA256"));
    return mac.doFinal(data);
  }

  private byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  private CommunicationCipher communication(int scalar) {
    KeyPair identity = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
    LibSECP256r1.initialize((ECPrivateKey) identity.getPrivate());
    LibSECP256r1.initialize((ECPublicKey) identity.getPublic());
    byte[] privateKey = new byte[32];
    privateKey[31] = (byte) scalar;
    ((ECPrivateKey) identity.getPrivate()).setS(privateKey, (short) 0, (short) privateKey.length);
    byte[] publicKey = publicKey(scalar);
    ((ECPublicKey) identity.getPublic()).setW(publicKey, (short) 0, (short) publicKey.length);
    return new CommunicationCipher(identity, sharedCipher);
  }

  private byte[] publicKey(int scalar) {
    return CURVE.getG().multiply(BigInteger.valueOf(scalar)).normalize().getEncoded(false);
  }

  private byte[] bytes(int length) {
    byte[] result = new byte[length];
    for (int index = 0; index < length; index++) {
      result[index] = (byte) (index * 17 + 3);
    }
    return result;
  }

  private byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private byte[] concat(byte[]... values) {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    for (byte[] value : values) {
      result.write(value, 0, value.length);
    }
    return result.toByteArray();
  }

  private int compare(byte[] left, byte[] right) {
    for (int index = 0; index < left.length; index++) {
      int difference = (left[index] & 0xFF) - (right[index] & 0xFF);
      if (difference != 0) {
        return difference;
      }
    }
    return 0;
  }
}
