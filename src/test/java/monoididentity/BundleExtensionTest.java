package monoididentity;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.IdentityCallerApplet.Data;

public class BundleExtensionTest {

  private static final byte[] DOMAIN = "Monoid Bundle Extension".getBytes(
    StandardCharsets.US_ASCII
  );

  private static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256r1");

  private static final AID CALLER_AID = AIDUtil.create("F001020304");

  private static final byte[] INDEX = { 3, 0, 1, 2, 3, 4, 5, 6, 7, 8 };

  private final Member a = new Member(1);
  private final Member b = new Member(2);
  private final Member c = new Member(3);
  private final Member d = new Member(4);

  @Test
  public void requestsMatchIndependentHmacAndEcdsaInBothDirections() throws Exception {
    Bundle bundle = createBundle();
    byte[] request = a.extension.extend(bundle, c.publicKey);

    Assertions.assertEquals(1, request[0]);
    Assertions.assertArrayEquals(bundle.hash, Arrays.copyOfRange(request, 1, 33));
    Assertions.assertArrayEquals(a.publicKey, Arrays.copyOfRange(request, 33, 98));
    Assertions.assertArrayEquals(c.publicKey, Arrays.copyOfRange(request, 98, 163));

    Assertions.assertArrayEquals(
      hostMac(bundle.key, request, DOMAIN),
      Arrays.copyOfRange(request, 163, 195)
    );

    Assertions.assertEquals(request.length - 196, request[195] & 0xFF);
    Assertions.assertTrue(hostVerify(request));
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(request));

    byte[] original = request.clone();

    Assertions.assertArrayEquals(
      c.publicKey,
      b.extension.requireRecipientPublicKey(bundle, request)
    );
    Assertions.assertArrayEquals(
      c.publicKey,
      b.extension.requireRecipientPublicKey(bundle, request)
    );
    Assertions.assertArrayEquals(original, request);

    byte[] hostRequest = hostRequest(bundle.hash, bundle.key, a, c.publicKey, DOMAIN);

    Assertions.assertArrayEquals(
      c.publicKey,
      b.extension.requireRecipientPublicKey(bundle, hostRequest)
    );
  }

  @Test
  public void requestsBindEveryFieldAndRejectMalformedFraming() throws Exception {
    Bundle bundle = createBundle();
    byte[] request = hostRequest(bundle.hash, bundle.key, a, c.publicKey, DOMAIN);

    for (int offset : new int[] { 0, 1, 32, 33, 97, 98, 162, 163, 194, 196, request.length - 1 }) {
      byte[] changed = request.clone();
      changed[offset] ^= 1;
      Assertions.assertThrows(RuntimeException.class, () ->
        b.extension.requireRecipientPublicKey(bundle, changed)
      );
    }

    for (int length : new int[] { 0, 1, 195, 196, 203, request.length - 1, request.length + 1 }) {
      byte[] changed = Arrays.copyOf(request, length);
      Assertions.assertThrows(CryptoException.class, () ->
        b.extension.requireRecipientPublicKey(bundle, changed)
      );
    }

    for (int length : new int[] { 0, 7, 73, 255 }) {
      byte[] changed = request.clone();
      changed[195] = (byte) length;
      Assertions.assertThrows(CryptoException.class, () ->
        b.extension.requireRecipientPublicKey(bundle, changed)
      );
    }

    Assertions.assertArrayEquals(
      c.publicKey,
      b.extension.requireRecipientPublicKey(bundle, request)
    );
  }

  @Test
  public void bothThePublicBundleHashAndPrivateRootAreRequired() throws Exception {
    Bundle bundle = createBundle();
    Bundle other = createBundle();
    byte[] request = a.extension.extend(bundle, c.publicKey);

    Assertions.assertThrows(ISOException.class, () ->
      b.extension.requireRecipientPublicKey(other, request)
    );

    // A matching public hash and a valid personal signature do not prove root possession.
    byte[] wrongRoot = hostRequest(bundle.hash, other.key, a, c.publicKey, DOMAIN);
    Assertions.assertTrue(hostVerify(wrongRoot));
    Assertions.assertThrows(CryptoException.class, () ->
      b.extension.requireRecipientPublicKey(bundle, wrongRoot)
    );

    byte[] otherDomain = hostRequest(
      bundle.hash,
      bundle.key,
      a,
      c.publicKey,
      "Monoid Bundle Sender Key".getBytes(StandardCharsets.US_ASCII)
    );
    Assertions.assertThrows(CryptoException.class, () ->
      b.extension.requireRecipientPublicKey(bundle, otherDomain)
    );
    Assertions.assertArrayEquals(
      c.publicKey,
      b.extension.requireRecipientPublicKey(bundle, request)
    );
  }

  @Test
  public void oneIdentityCannotApproveItsOwnExtensionTwice() {
    Bundle bundle = createBundle();
    byte[] request = a.extension.extend(bundle, c.publicKey);
    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      a.extension.requireRecipientPublicKey(bundle, request)
    );

    Assertions.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, exception.getReason());
    Assertions.assertArrayEquals(
      c.publicKey,
      b.extension.requireRecipientPublicKey(bundle, request)
    );
  }

  @Test
  public void aValidRootMacDoesNotReplaceTheInitiatorsPersonalSignature() throws Exception {
    Bundle bundle = createBundle();
    byte[] request = a.extension.extend(bundle, c.publicKey);
    byte[] wrongSignature = hostSign(request, c.scalar, DOMAIN);

    Assertions.assertArrayEquals(
      hostMac(bundle.key, wrongSignature, DOMAIN),
      Arrays.copyOfRange(wrongSignature, 163, 195)
    );
    Assertions.assertFalse(hostVerify(wrongSignature));
    Assertions.assertThrows(CryptoException.class, () ->
      b.extension.requireRecipientPublicKey(bundle, wrongSignature)
    );
  }

  @Test
  public void aTargetCannotReuseItsRequestToImpersonateAnExistingMember() throws Exception {
    Bundle bundle = createBundle();
    byte[] request = a.extension.extend(bundle, c.publicKey);

    // C knows its own private key but has not joined and cannot calculate a new root MAC.
    byte[] changed = request.clone();
    System.arraycopy(c.publicKey, 0, changed, 33, 65);
    System.arraycopy(d.publicKey, 0, changed, 98, 65);
    byte[] forged = hostSign(changed, c.scalar, DOMAIN);

    Assertions.assertTrue(hostVerify(forged));
    Assertions.assertArrayEquals(
      Arrays.copyOfRange(request, 163, 195),
      Arrays.copyOfRange(forged, 163, 195)
    );
    Assertions.assertFalse(
      Arrays.equals(hostMac(bundle.key, forged, DOMAIN), Arrays.copyOfRange(forged, 163, 195))
    );
    Assertions.assertThrows(CryptoException.class, () ->
      a.extension.requireRecipientPublicKey(bundle, forged)
    );
    Assertions.assertThrows(CryptoException.class, () ->
      b.extension.requireRecipientPublicKey(bundle, forged)
    );
  }

  @Test
  public void aNewMemberCanCommunicateAndApproveWithoutSynchronizingOldMemberLists() {
    Bundle bundleA = createBundle();
    Bundle bundleB = join(b, a, bundleA.encryptFor(b.publicKey, a.publicKey, a.communication));
    byte[] request = a.extension.extend(bundleA, c.publicKey);
    byte[] target = b.extension.requireRecipientPublicKey(bundleB, request);
    Bundle bundleC = join(c, b, bundleB.encryptFor(target, b.publicKey, b.communication));

    Assertions.assertFalse(bundleA.contains(c.publicKey));
    Assertions.assertFalse(bundleB.contains(c.publicKey));
    Assertions.assertTrue(bundleC.contains(c.publicKey));
    assertTransfer(c, bundleC, a, bundleA);
    assertTransfer(a, bundleA, c, bundleC);

    byte[] nextRequest = c.extension.extend(bundleC, d.publicKey);
    byte[] nextTarget = a.extension.requireRecipientPublicKey(bundleA, nextRequest);
    Bundle bundleD = join(d, a, bundleA.encryptFor(nextTarget, a.publicKey, a.communication));

    Assertions.assertFalse(bundleA.contains(d.publicKey));
    Assertions.assertFalse(bundleC.contains(d.publicKey));
    assertTransfer(d, bundleD, c, bundleC);
    assertTransfer(c, bundleC, d, bundleD);
  }

  @Test
  public void repeatedEnrollmentMatchesTheSameRootAcrossDifferentSnapshots() {
    Bundle bundleA = createBundle();
    Bundle bundleC = join(c, a, bundleA.encryptFor(c.publicKey, a.publicKey, a.communication));
    Bundle originalSnapshot = join(
      b,
      a,
      bundleA.encryptFor(b.publicKey, a.publicKey, a.communication)
    );
    Bundle laterSnapshot = join(
      b,
      c,
      bundleC.encryptFor(b.publicKey, c.publicKey, c.communication)
    );

    Assertions.assertFalse(originalSnapshot.contains(c.publicKey));
    Assertions.assertTrue(laterSnapshot.contains(c.publicKey));
    Assertions.assertTrue(originalSnapshot.matches(laterSnapshot));
    Assertions.assertTrue(laterSnapshot.matches(originalSnapshot));
    Assertions.assertArrayEquals(originalSnapshot.hash, laterSnapshot.hash);
    Assertions.assertFalse(originalSnapshot.matches(createBundle()));
  }

  private Bundle createBundle() {
    return Bundle.create(b.publicKey, a.publicKey, a.communication);
  }

  private static Bundle join(Member recipient, Member sender, byte[] packet) {
    return Bundle.decrypt(
      sender.publicKey,
      recipient.publicKey,
      packet,
      recipient.communication,
      null
    );
  }

  private static void assertTransfer(
    Member sender,
    Bundle senderBundle,
    Member recipient,
    Bundle recipientBundle
  ) {
    byte[] data = "Bundle member data".getBytes(StandardCharsets.US_ASCII);
    byte[] encrypted = sender.items.encrypt(
      sender.communication,
      senderBundle,
      Constants.SAFE_FALSE,
      CALLER_AID,
      sender.publicKey,
      INDEX,
      null,
      null,
      Constants.SAFE_TRUE,
      null,
      new Data(data)
    );

    Assertions.assertArrayEquals(
      concat(new byte[] { 0x5A, (byte) 0xFE }, data),
      recipient.items.decrypt(
        Constants.SAFE_FALSE,
        recipient.communication,
        recipientBundle,
        CALLER_AID,
        recipient.publicKey,
        INDEX,
        null,
        null,
        null,
        new Data(encrypted)
      )
    );
    Assertions.assertThrows(ISOException.class, () ->
      sender.items.decrypt(
        Constants.SAFE_FALSE,
        sender.communication,
        senderBundle,
        CALLER_AID,
        sender.publicKey,
        INDEX,
        null,
        null,
        null,
        new Data(encrypted)
      )
    );
  }

  /** JCE computes and verifies the wire proof independently of the Java Card helpers. */
  private static byte[] hostRequest(
    byte[] hash,
    byte[] root,
    Member initiator,
    byte[] target,
    byte[] domain
  ) throws Exception {
    byte[] request = new byte[196];
    request[0] = 1;
    System.arraycopy(hash, 0, request, 1, 32);
    System.arraycopy(initiator.publicKey, 0, request, 33, 65);
    System.arraycopy(target, 0, request, 98, 65);
    System.arraycopy(hostMac(root, request, domain), 0, request, 163, 32);

    return hostSign(request, initiator.scalar, domain);
  }

  private static byte[] hostMac(byte[] root, byte[] request, byte[] domain) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(root, "HmacSHA256"));
    mac.update(domain);
    mac.update(request, 0, 163);

    return mac.doFinal();
  }

  private static byte[] hostSign(byte[] request, int scalar, byte[] domain) throws Exception {
    java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA");
    signer.initSign(
      KeyFactory.getInstance("EC").generatePrivate(
        new ECPrivateKeySpec(BigInteger.valueOf(scalar), hostCurve())
      )
    );
    signer.update(domain);
    signer.update(request, 0, 195);
    byte[] signature = signer.sign();
    byte[] result = Arrays.copyOf(request, 196 + signature.length);
    result[195] = (byte) signature.length;
    System.arraycopy(signature, 0, result, 196, signature.length);

    return result;
  }

  private static boolean hostVerify(byte[] request) throws Exception {
    ECPoint point = new ECPoint(
      new BigInteger(1, Arrays.copyOfRange(request, 34, 66)),
      new BigInteger(1, Arrays.copyOfRange(request, 66, 98))
    );
    java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(
      KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, hostCurve()))
    );
    verifier.update(DOMAIN);
    verifier.update(request, 0, 195);

    return verifier.verify(request, 196, request.length - 196);
  }

  private static ECParameterSpec hostCurve() throws Exception {
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec("secp256r1"));

    return parameters.getParameterSpec(ECParameterSpec.class);
  }

  private static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream result = new ByteArrayOutputStream();

    for (byte[] part : parts) {
      result.write(part, 0, part.length);
    }

    return result.toByteArray();
  }

  private static final class Member {

    private final int scalar;
    private final byte[] publicKey;
    private final CommunicationCipher communication;
    private final BundleExtension extension;
    private final ItemCipher items;

    private Member(int scalar) {
      this.scalar = scalar;
      publicKey = CURVE.getG().multiply(BigInteger.valueOf(scalar)).normalize().getEncoded(false);
      KeyPair identity = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
      ECPrivateKey privateKey = (ECPrivateKey) identity.getPrivate();
      ECPublicKey publicPart = (ECPublicKey) identity.getPublic();
      LibSECP256r1.initialize(privateKey);
      LibSECP256r1.initialize(publicPart);
      byte[] privateBytes = new byte[32];
      privateBytes[31] = (byte) scalar;
      privateKey.setS(privateBytes, (short) 0, (short) privateBytes.length);
      publicPart.setW(publicKey, (short) 0, (short) publicKey.length);
      AESGcmCipher cipher = new AESGcmCipher();
      byte[] hmacBlock = new byte[64];
      communication = new CommunicationCipher(identity, cipher, hmacBlock);
      extension = new BundleExtension(identity, hmacBlock);
      items = new ItemCipher(cipher, hmacBlock);
    }
  }
}
