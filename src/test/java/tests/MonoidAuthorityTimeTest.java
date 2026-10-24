package tests;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoididentity.IdentityShareable;
import monoididentity.MonoidIdentityApplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Independent host signatures through real SIO context switches; no hardware firewall claim. */
public class MonoidAuthorityTimeTest {

  private static final AID IDENTITY_AID = AIDUtil.create("f06d6f6e6f69640001");
  private static final AID MONOID_AID = AIDUtil.create("f06d6f6e6f69640201");
  private static final AID CALLER_AID = AIDUtil.create("f01234567801");

  private static final byte[] DOMAIN = "Monoid Authority Time".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] CHALLENGE = hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  );
  private static final byte[] PUBLIC_KEY = hex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
  );

  // Fixed Node WebCrypto P-256/SHA-256 signatures, using the public test scalar d = 1.
  // The raw message matches workers/authority/src/crypto.ts: DOMAIN || version || u64be || nonce.
  private static final String[] WORKER_SIGNATURES = {
    "d5c7049581c748926db87acb8ce8aba5132eae4577bede88cf83b1dda6a908b3e" +
    "6ff79381dec01bbb7f72e9e7b14066370255be43947c5428e956d45097fb8d9",
    "004cd8d07bf717413c357d0f0e02feb2983ff3ca826a02e0181304c91bf1bf90" +
    "8f8e85070f59e4f34b9b706319356b58968fe4b2d34cb60a5eacde7f1e3b5c71",
    "a4409d18c61a3629a35a6579f272c23d5aca912f3e6d774d0347734657b5d51b" +
    "00d9f58f759b214ce8fc2895d8fecca1c07aa52c1b870ab2be787a6106e9186d",
  };

  private TimeRuntime runtime;
  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    initialize(true);
  }

  @Test
  public void workerVectorsVerifyWithJceAndHandleUnsignedDerIntegers() throws Exception {
    byte[] data = data(1792720500L);

    Assertions.assertArrayEquals(
      hex("01000000006adabe74000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
      data
    );

    Assertions.assertTrue((hex(WORKER_SIGNATURES[0])[0] & 0x80) != 0);
    Assertions.assertTrue((hex(WORKER_SIGNATURES[1])[32] & 0x80) != 0);
    Assertions.assertEquals(0, hex(WORKER_SIGNATURES[1])[0]);
    Assertions.assertEquals(0, hex(WORKER_SIGNATURES[2])[32]);

    ECParameterSpec curve = curve();
    ECPoint point = new ECPoint(
      new BigInteger(1, Arrays.copyOfRange(PUBLIC_KEY, 1, 33)),
      new BigInteger(1, Arrays.copyOfRange(PUBLIC_KEY, 33, 65))
    );
    Signature jce = Signature.getInstance("SHA256withECDSAinP1363Format");

    for (String vector : WORKER_SIGNATURES) {
      byte[] signature = hex(vector);

      jce.initVerify(
        KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, curve))
      );
      jce.update(message(DOMAIN, data));

      Assertions.assertTrue(jce.verify(signature));
      Assertions.assertEquals(0x9000, verify(data, signature, CHALLENGE).getSW());
      Assertions.assertEquals(0x9000, verify(data, signature, CHALLENGE).getSW());
    }
  }

  @Test
  public void independentJceSignaturesBindTimeChallengePurposeAndPinnedKey() throws Exception {
    byte[] data = data(0x0000010203040506L);
    byte[] signature = sign(data, DOMAIN, BigInteger.ONE);

    Assertions.assertEquals(0x9000, verify(data, signature, CHALLENGE).getSW());

    for (int offset = 1; offset < data.length; offset++) {
      byte[] changed = data.clone();
      changed[offset] ^= 1;

      Assertions.assertEquals(0x6982, verify(changed, signature, CHALLENGE).getSW());
    }

    byte[] otherChallenge = CHALLENGE.clone();
    otherChallenge[0] ^= 1;

    Assertions.assertEquals(0x6982, verify(data, signature, otherChallenge).getSW());
    Assertions.assertEquals(
      0x6982,
      verify(data, sign(data, new byte[0], BigInteger.ONE), CHALLENGE).getSW()
    );
    Assertions.assertEquals(
      0x6982,
      verify(data, sign(data, DOMAIN, BigInteger.valueOf(2)), CHALLENGE).getSW()
    );

    byte[] digest = MessageDigest.getInstance("SHA-256").digest(message(DOMAIN, data));

    Assertions.assertEquals(
      0x6982,
      verify(data, sign(digest, new byte[0], BigInteger.ONE), CHALLENGE).getSW()
    );

    for (int offset : new int[] { 0, 31, 32, 63 }) {
      byte[] changed = signature.clone();
      changed[offset] ^= 1;

      Assertions.assertEquals(0x6982, verify(data, changed, CHALLENGE).getSW());
    }

    Assertions.assertEquals(0x6982, verify(data, new byte[64], CHALLENGE).getSW());

    byte[] oversizedScalar = new byte[64];
    Arrays.fill(oversizedScalar, (byte) 0xFF);

    Assertions.assertEquals(0x6982, verify(data, oversizedScalar, CHALLENGE).getSW());
    Assertions.assertEquals(0x9000, verify(data, signature, CHALLENGE).getSW());
  }

  @Test
  public void malformedVersionAndExactInputLengthsReturnWrongData() throws Exception {
    byte[] data = data(1792720500L);
    byte[] signature = sign(data, DOMAIN, BigInteger.ONE);

    for (byte[] invalid : new byte[][] { null, new byte[0], new byte[40], new byte[42] }) {
      Assertions.assertEquals(0x6A80, verify(invalid, signature, CHALLENGE).getSW());
    }

    for (byte[] invalid : new byte[][] { null, new byte[0], new byte[63], new byte[65] }) {
      Assertions.assertEquals(0x6A80, verify(data, invalid, CHALLENGE).getSW());
    }

    for (byte[] invalid : new byte[][] { null, new byte[0], new byte[31], new byte[33] }) {
      Assertions.assertEquals(0x6A80, verify(data, signature, invalid).getSW());
    }

    for (byte version : new byte[] { 0, 2, (byte) 0xFF }) {
      byte[] changed = data.clone();
      changed[0] = version;

      Assertions.assertEquals(
        0x6A80,
        verify(changed, sign(changed, DOMAIN, BigInteger.ONE), CHALLENGE).getSW()
      );
    }
  }

  @Test
  public void missingAuthorityAndMissingRuntimeCallerReturnSecurityStatus() {
    byte[] data = data(1792720500L);
    byte[] signature = hex(WORKER_SIGNATURES[0]);

    runtime.hideCaller = true;

    Assertions.assertEquals(0x6982, verify(data, signature, CHALLENGE).getSW());

    runtime.hideCaller = false;

    Assertions.assertEquals(0x9000, verify(data, signature, CHALLENGE).getSW());

    initialize(false);

    Assertions.assertEquals(0x6982, verify(data, signature, CHALLENGE).getSW());
  }

  @Test
  public void verifierIsLazyReusableAndPreservedThroughIdentityAndCardReset() throws Exception {
    byte[] data = data(1792720500L);
    byte[] signature = hex(WORKER_SIGNATURES[0]);

    Assertions.assertNull(verifier());
    Assertions.assertEquals(0x9000, verify(data, signature, CHALLENGE).getSW());

    Object verifier = verifier();

    Assertions.assertNotNull(verifier);
    Assertions.assertTrue(simulator.selectApplet(MONOID_AID));
    Assertions.assertEquals(0x9000, simulator.transmitCommand(new CommandAPDU(0, 2, 0, 0)).getSW());
    Assertions.assertSame(verifier, verifier());
    Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
    Assertions.assertEquals(0x9000, verify(data, signature, CHALLENGE).getSW());

    simulator.reset();

    Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
    Assertions.assertEquals(0x9000, verify(data, signature, CHALLENGE).getSW());
    Assertions.assertSame(verifier, verifier());
  }

  private void initialize(boolean authority) {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");

    runtime = new TimeRuntime();
    simulator = new CardSimulator(runtime);

    if (authority) {
      byte[] url = "https://authority.example/".getBytes(StandardCharsets.UTF_8);
      byte[] installation = new byte[69 + url.length];
      installation[2] = (byte) (66 + url.length);
      installation[3] = 2;
      System.arraycopy(PUBLIC_KEY, 0, installation, 4, PUBLIC_KEY.length);
      System.arraycopy(url, 0, installation, 69, url.length);

      simulator.installApplet(
        IDENTITY_AID,
        MonoidIdentityApplet.class,
        installation,
        (short) 0,
        (byte) installation.length
      );
    } else {
      simulator.installApplet(IDENTITY_AID, MonoidIdentityApplet.class);
    }

    simulator.installApplet(CALLER_AID, TimeCallerApplet.class);
    simulator.installApplet(MONOID_AID, TimeCallerApplet.class);

    Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
  }

  private Object verifier() throws Exception {
    Object identity = runtime.lookupApplet(IDENTITY_AID).getApplet();
    Field field = MonoidIdentityApplet.class.getDeclaredField("authorityTime");
    field.setAccessible(true);

    return field.get(identity);
  }

  private ResponseAPDU verify(byte[] data, byte[] signature, byte[] challenge) {
    ByteArrayOutputStream request = new ByteArrayOutputStream();

    for (byte[] input : new byte[][] { data, signature, challenge }) {
      request.write(input == null ? 255 : input.length);

      if (input != null) {
        request.write(input, 0, input.length);
      }
    }

    return simulator.transmitCommand(new CommandAPDU(0, 1, 0, 0, request.toByteArray()));
  }

  private static byte[] data(long seconds) {
    return ByteBuffer.allocate(41).put((byte) 1).putLong(seconds).put(CHALLENGE).array();
  }

  private static byte[] sign(byte[] data, byte[] domain, BigInteger scalar) throws Exception {
    PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(
      new ECPrivateKeySpec(scalar, curve())
    );
    Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
    signer.initSign(key);
    signer.update(message(domain, data));

    return signer.sign();
  }

  private static ECParameterSpec curve() throws Exception {
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec("secp256r1"));

    return parameters.getParameterSpec(ECParameterSpec.class);
  }

  private static byte[] message(byte[] domain, byte[] data) {
    byte[] message = Arrays.copyOf(domain, domain.length + data.length);
    System.arraycopy(data, 0, message, domain.length, data.length);

    return message;
  }

  private static byte[] hex(String value) {
    byte[] result = new byte[value.length() / 2];

    for (int index = 0; index < result.length; index++) {
      result[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
    }

    return result;
  }

  private static final class TimeRuntime extends ShareableSimulatorRuntime {

    private boolean hideCaller;

    @Override
    public AID getPreviousContextAID() {
      return hideCaller ? null : super.getPreviousContextAID();
    }
  }

  /** Sends only global arrays across the Identity boundary and detects any input mutation. */
  public static class TimeCallerApplet extends Applet {

    public static void install(byte[] buffer, short offset, byte length) {
      new TimeCallerApplet().register();
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        return;
      }

      byte[] aid = AppletTest.aidBytes(IDENTITY_AID);
      IdentityShareable identity = (IdentityShareable) JCSystem.getAppletShareableInterfaceObject(
        JCSystem.lookupAID(aid, (short) 0, (byte) aid.length),
        (byte) 0
      );

      byte[] buffer = apdu.getBuffer();

      if (buffer[ISO7816.OFFSET_INS] == 2) {
        identity.prepareReset();
        JCSystem.beginTransaction();
        identity.reset();
        JCSystem.commitTransaction();

        return;
      }

      short length = apdu.setIncomingAndReceive();
      short offset = apdu.getOffsetCdata();
      byte[] original = new byte[length];
      Util.arrayCopyNonAtomic(buffer, offset, original, (short) 0, length);

      byte[] data = global(buffer, offset);
      offset += (short) (1 + (data == null ? 0 : data.length));

      byte[] signature = global(buffer, offset);
      offset += (short) (1 + (signature == null ? 0 : signature.length));

      byte[] challenge = global(buffer, offset);

      identity.verifyAuthorityTime(data, signature, challenge);

      short start = 0;
      assertUnchanged(data, original, start);
      start += (short) (1 + data.length);
      assertUnchanged(signature, original, start);
      start += (short) (1 + signature.length);
      assertUnchanged(challenge, original, start);
    }

    private static byte[] global(byte[] input, short offset) {
      short length = (short) (input[offset++] & 0xFF);

      if (length == 255) {
        return null;
      }

      byte[] output = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, length);
      Util.arrayCopyNonAtomic(input, offset, output, (short) 0, length);

      return output;
    }

    private static void assertUnchanged(byte[] value, byte[] original, short offset) {
      if (
        Util.arrayCompare(value, (short) 0, original, (short) (offset + 1), (short) value.length) !=
        0
      ) {
        ISOException.throwIt((short) 0x6F01);
      }
    }
  }
}
