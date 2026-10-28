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
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
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

public class ItemCipherSenderTest {

  private static final AID CALLER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );

  private static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256r1");
  private static final byte[] INDEX = { 3, 0, 1, 2, 3, 4, 5, 6, 7, 8 };
  private static final byte[] KEY = { 1, 2, 3 };
  private static final byte[] ALIAS = "sender item".getBytes(StandardCharsets.UTF_8);

  private final AESGcmCipher sharedCipher = new AESGcmCipher();
  private final ItemCipher cipher = new ItemCipher(sharedCipher);

  @Test
  public void senderEnvelopeMatchesIndependentHmacAndGcmInBothDirections() throws Exception {
    TestIdentity sender = new TestIdentity(1, sharedCipher);
    TestIdentity receiver = new TestIdentity(2, sharedCipher);
    Bundle bundle = bundle(sender, receiver);

    for (int length : new int[] { 0, 17, 64, 257 }) {
      byte[] data = bytes(length);
      byte[] encrypted = encrypt(sender, bundle, receiver.publicKey, data);
      byte[] plaintext = plaintext(data);
      Assertions.assertEquals(160 + length, encrypted.length);
      Assertions.assertEquals(2, encrypted[0]);
      Assertions.assertArrayEquals(bundle.hash, Arrays.copyOfRange(encrypted, 1, 33));
      Assertions.assertArrayEquals(sender.publicKey, Arrays.copyOfRange(encrypted, 33, 98));
      Assertions.assertArrayEquals(
        plaintext,
        cryptOnHost(
          Cipher.DECRYPT_MODE,
          bundle.key,
          encrypted,
          Arrays.copyOfRange(encrypted, 142, encrypted.length),
          true
        )
      );
      Assertions.assertArrayEquals(plaintext, decrypt(receiver, bundle, null, new Data(encrypted)));

      byte[] hostPlaintext = plaintext.clone();
      hostPlaintext[0] = (byte) (Constants.SAFE_FALSE >> 8);
      hostPlaintext[1] = (byte) Constants.SAFE_FALSE;
      byte[] hostCiphertext = cryptOnHost(
        Cipher.ENCRYPT_MODE,
        bundle.key,
        encrypted,
        hostPlaintext,
        true
      );
      byte[] hostEnvelope = encrypted.clone();
      System.arraycopy(hostCiphertext, 0, hostEnvelope, 142, hostCiphertext.length);
      Assertions.assertArrayEquals(
        hostPlaintext,
        decrypt(receiver, bundle, null, new Data(hostEnvelope))
      );
    }
  }

  @Test
  public void eachMemberOnlyDecryptsOtherMembersAndTheHeaderAuthenticatesTheSender() {
    TestIdentity first = new TestIdentity(1, sharedCipher);
    TestIdentity second = new TestIdentity(2, sharedCipher);
    TestIdentity third = new TestIdentity(3, sharedCipher);
    TestIdentity outsider = new TestIdentity(4, sharedCipher);
    TestIdentity[] members = { first, second, third };
    Bundle bundle = bundle(members);
    byte[] data = bytes(32);

    for (TestIdentity sender : members) {
      byte[] encrypted = encrypt(sender, bundle, outsider.publicKey, data);

      for (TestIdentity receiver : members) {
        if (sender == receiver) {
          ISOException exception = Assertions.assertThrows(ISOException.class, () ->
            decrypt(receiver, bundle, outsider.publicKey, new Data(encrypted))
          );
          Assertions.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, exception.getReason());
        } else {
          Assertions.assertArrayEquals(
            plaintext(data),
            decrypt(receiver, bundle, receiver.publicKey, new Data(encrypted))
          );
        }
      }
    }

    byte[] encrypted = encrypt(first, bundle, null, data);
    byte[] forgedSender = encrypted.clone();
    System.arraycopy(third.publicKey, 0, forgedSender, 33, 65);
    Assertions.assertThrows(CryptoException.class, () ->
      decrypt(second, bundle, first.publicKey, new Data(forgedSender))
    );

    System.arraycopy(outsider.publicKey, 0, forgedSender, 33, 65);
    // An unknown sender is authenticated by its derived key, not an enrollment roster.
    Assertions.assertThrows(CryptoException.class, () ->
      decrypt(second, bundle, first.publicKey, new Data(forgedSender))
    );
    Assertions.assertArrayEquals(
      plaintext(data),
      decrypt(second, bundle, null, new Data(encrypted))
    );
  }

  @Test
  public void joiningPreventsOldSelfHpkeRecoveryButPreservesIncomingHpke() {
    TestIdentity first = new TestIdentity(1, sharedCipher);
    TestIdentity second = new TestIdentity(2, sharedCipher);
    TestIdentity outsider = new TestIdentity(3, sharedCipher);
    byte[] data = bytes(32);
    byte[] self = encrypt(first, null, first.publicKey, data);
    Assertions.assertArrayEquals(
      plaintext(data),
      decrypt(first, null, first.publicKey, new Data(self))
    );

    Bundle bundle = bundle(first, second);
    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      decrypt(first, bundle, first.publicKey, new Data(self))
    );
    Assertions.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, exception.getReason());
    Assertions.assertThrows(CryptoException.class, () ->
      decrypt(first, bundle, second.publicKey, new Data(self))
    );

    byte[] incoming = encrypt(outsider, null, first.publicKey, data);
    Assertions.assertArrayEquals(
      plaintext(data),
      decrypt(first, bundle, outsider.publicKey, new Data(incoming))
    );
  }

  @Test
  public void callerIsolationAndTheNewSenderKeyRejectOtherDomainsAndTheOldFormat()
    throws Exception {
    TestIdentity sender = new TestIdentity(1, sharedCipher);
    TestIdentity receiver = new TestIdentity(2, sharedCipher);
    Bundle bundle = bundle(sender, receiver);
    byte[] data = bytes(256);
    byte[] encrypted = encrypt(sender, bundle, null, data);
    byte[] caller = aidBytes(CALLER_AID);
    byte[] changed = caller.clone();
    changed[changed.length - 1] ^= 1;
    byte[] extended = Arrays.copyOf(caller, caller.length + 1);

    for (byte[] other : new byte[][] { changed, extended }) {
      AID otherCaller = new AID(other, (short) 0, (byte) other.length);
      Assertions.assertThrows(CryptoException.class, () ->
        cipher.decrypt(
          Constants.SAFE_FALSE,
          receiver.cipher,
          bundle,
          otherCaller,
          receiver.publicKey,
          INDEX,
          KEY,
          ALIAS,
          null,
          new Data(encrypted)
        )
      );
    }

    byte[] callerOnly = encrypted.clone();
    byte[] oldCiphertext = cryptOnHost(
      Cipher.ENCRYPT_MODE,
      bundle.key,
      callerOnly,
      plaintext(data),
      false
    );
    System.arraycopy(oldCiphertext, 0, callerOnly, 142, oldCiphertext.length);
    Assertions.assertThrows(CryptoException.class, () ->
      decrypt(receiver, bundle, null, new Data(callerOnly))
    );

    byte[] oldEnvelope = new byte[callerOnly.length - 65];
    System.arraycopy(callerOnly, 0, oldEnvelope, 0, 33);
    System.arraycopy(callerOnly, 98, oldEnvelope, 33, callerOnly.length - 98);
    Assertions.assertThrows(RuntimeException.class, () ->
      decrypt(receiver, bundle, sender.publicKey, new Data(oldEnvelope))
    );
    Assertions.assertArrayEquals(
      plaintext(data),
      decrypt(receiver, bundle, null, new Data(encrypted))
    );
  }

  @Test
  public void callbacksCannotChangeMetadataOrTheExternalHpkeSender() {
    TestIdentity sender = new TestIdentity(1, sharedCipher);
    TestIdentity receiver = new TestIdentity(2, sharedCipher);
    Bundle bundle = bundle(sender, receiver);
    byte[] data = bytes(65);

    for (Bundle current : new Bundle[] { null, bundle }) {
      byte[] index = INDEX.clone();
      byte[] key = KEY.clone();
      byte[] alias = ALIAS.clone();
      byte[] recipient = receiver.publicKey.clone();
      byte[] encrypted = cipher.encrypt(
        sender.cipher,
        current,
        current == null ? Constants.SAFE_TRUE : Constants.SAFE_FALSE,
        CALLER_AID,
        sender.publicKey,
        index,
        key,
        alias,
        Constants.SAFE_TRUE,
        recipient,
        new Data(data) {
          @Override
          public short getLength() {
            Arrays.fill(index, (byte) 0);
            Arrays.fill(key, (byte) 0);
            Arrays.fill(alias, (byte) 0);
            Arrays.fill(recipient, (byte) 0);
            return super.getLength();
          }
        }
      );

      System.arraycopy(INDEX, 0, index, 0, index.length);
      System.arraycopy(KEY, 0, key, 0, key.length);
      System.arraycopy(ALIAS, 0, alias, 0, alias.length);
      byte[] externalSender = sender.publicKey.clone();
      Assertions.assertArrayEquals(
        plaintext(data),
        cipher.decrypt(
          Constants.SAFE_FALSE,
          receiver.cipher,
          current,
          CALLER_AID,
          receiver.publicKey,
          index,
          key,
          alias,
          externalSender,
          new Data(encrypted) {
            @Override
            public short getLength() {
              Arrays.fill(index, (byte) 0);
              Arrays.fill(key, (byte) 0);
              Arrays.fill(alias, (byte) 0);
              Arrays.fill(externalSender, (byte) 0);
              return super.getLength();
            }
          }
        )
      );
    }
  }

  private Bundle bundle(TestIdentity... members) {
    byte[][] publicKeys = new byte[members.length - 1][];

    for (int index = 1; index < members.length; index++) {
      publicKeys[index - 1] = members[index].publicKey;
    }

    return Bundle.create(concat(publicKeys), members[0].publicKey, members[0].cipher);
  }

  private byte[] encrypt(
    TestIdentity sender,
    Bundle bundle,
    byte[] recipientPublicKey,
    byte[] data
  ) {
    return cipher.encrypt(
      sender.cipher,
      bundle,
      bundle == null ? Constants.SAFE_TRUE : Constants.SAFE_FALSE,
      CALLER_AID,
      sender.publicKey,
      INDEX,
      KEY,
      ALIAS,
      Constants.SAFE_TRUE,
      recipientPublicKey,
      new Data(data)
    );
  }

  private byte[] decrypt(
    TestIdentity receiver,
    Bundle bundle,
    byte[] senderPublicKey,
    Data encrypted
  ) {
    return cipher.decrypt(
      Constants.SAFE_FALSE,
      receiver.cipher,
      bundle,
      CALLER_AID,
      receiver.publicKey,
      INDEX,
      KEY,
      ALIAS,
      senderPublicKey,
      encrypted
    );
  }

  private byte[] cryptOnHost(
    int mode,
    byte[] root,
    byte[] envelope,
    byte[] input,
    boolean bindSender
  ) throws Exception {
    byte[] caller = aidBytes(CALLER_AID);
    byte[] senderKey = hmac(
      root,
      concat(
        ascii(bindSender ? "Monoid Bundle Sender Key" : "Monoid Bundle Caller Key"),
        new byte[] { (byte) caller.length },
        caller,
        bindSender ? Arrays.copyOfRange(envelope, 33, 98) : new byte[0]
      )
    );
    byte[] prk = hmac(Arrays.copyOfRange(envelope, 98, 130), senderKey);
    byte[] key = Arrays.copyOf(
      hmac(prk, concat(ascii("Monoid Bundle Item Key"), metadataContext(), new byte[] { 1 })),
      16
    );
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
      mode,
      new SecretKeySpec(key, "AES"),
      new GCMParameterSpec(128, Arrays.copyOfRange(envelope, 130, 142))
    );
    return cipher.doFinal(input);
  }

  private byte[] metadataContext() throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    DataOutputStream output = new DataOutputStream(bytes);
    output.write(ascii("Monoid Item"));
    output.writeByte(2);
    byte[] caller = aidBytes(CALLER_AID);
    output.writeByte(caller.length);
    output.write(caller);
    output.write(INDEX);
    output.writeShort(KEY.length);
    output.write(KEY);
    output.writeShort(ALIAS.length);
    output.write(ALIAS);
    return MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
  }

  private byte[] hmac(byte[] key, byte[] input) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    return mac.doFinal(input);
  }

  private byte[] plaintext(byte[] data) {
    return concat(new byte[] { 0x5A, (byte) 0xFE }, data);
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

  private static final class TestIdentity {

    private final byte[] publicKey;
    private final CommunicationCipher cipher;

    private TestIdentity(int scalar, AESGcmCipher sharedCipher) {
      publicKey = CURVE.getG().multiply(BigInteger.valueOf(scalar)).normalize().getEncoded(false);
      KeyPair identity = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
      ECPrivateKey privatePart = (ECPrivateKey) identity.getPrivate();
      ECPublicKey publicPart = (ECPublicKey) identity.getPublic();
      LibSECP256r1.initialize(privatePart);
      LibSECP256r1.initialize(publicPart);
      byte[] privateKey = new byte[32];
      privateKey[31] = (byte) scalar;
      privatePart.setS(privateKey, (short) 0, (short) privateKey.length);
      publicPart.setW(publicKey, (short) 0, (short) publicKey.length);
      cipher = new CommunicationCipher(identity, sharedCipher);
    }
  }
}
