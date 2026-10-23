package tests;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.crypto.SymmetricSignatureImpl;
import com.licel.jcardsim.smartcardio.CardSimulator;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import monoid.CurveSECP256r1;
import monoid.KeyDerivation;
import monoid.LibHMACSha512;
import monoid.Monoid001Derivation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class Monoid001DerivationTest {

  private static final byte[] MASTER = Hex.decode(
    "088cd0290439e4f44a9ce20c88c5c0fe01003700a6ab01da261eb736f31ef6ff6acd" +
    "06abbc286ebe3752d82f1460c6ded8f3bcdee179054368c105d74ef466ff"
  );
  private static final byte[] CONTEXT = Hex.decode("007f80ff0001");

  private Monoid001Derivation derivation;
  private CardSimulator simulator;

  @BeforeEach
  public void initialize() {
    simulator = new CardSimulator();
    LibHMACSha512.init();
    KeyDerivation.init();
    derivation = new Monoid001Derivation();
  }

  @AfterEach
  public void dispose() {
    KeyDerivation.dispose();
    LibHMACSha512.dispose();
  }

  @Test
  public void selectedBackendMatchesHKDFVectors() throws Exception {
    Field signature = LibHMACSha512.class.getDeclaredField("sharedSignature");
    signature.setAccessible(true);
    Assertions.assertNotNull(signature.get(null));
    checkVectors();
  }

  @Test
  public void softwareBackendMatchesHKDFVectors() throws Exception {
    LibHMACSha512.dispose();
    Field digest = LibHMACSha512.class.getDeclaredField("sharedDigest");
    digest.setAccessible(true);
    digest.set(null, MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false));
    checkVectors();
  }

  @Test
  public void selectedBackendOverwritesPersistentScratchAcrossReset() throws Exception {
    checkWorkspace();
  }

  @Test
  public void softwareBackendOverwritesPersistentScratchAcrossReset() throws Exception {
    LibHMACSha512.dispose();
    Field digest = LibHMACSha512.class.getDeclaredField("sharedDigest");
    digest.setAccessible(true);
    digest.set(null, MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false));
    checkWorkspace();
  }

  private void checkWorkspace() throws Exception {
    byte[] first = derivation.derive(MASTER, CONTEXT).getKey().clone();
    Field field = Monoid001Derivation.class.getDeclaredField("workspace");
    field.setAccessible(true);
    byte[] workspace = (byte[]) field.get(derivation);
    Assertions.assertEquals(64, workspace.length);
    Assertions.assertEquals(JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(workspace));
    Field blockField = LibHMACSha512.class.getDeclaredField("sharedBlock");
    blockField.setAccessible(true);
    byte[] block = (byte[]) blockField.get(null);
    if (block != null) {
      Assertions.assertEquals(128, block.length);
      Assertions.assertEquals(JCSystem.CLEAR_ON_RESET, JCSystem.isTransient(block));
    }

    for (int length : new int[] { 0, 127, 128, 513 }) {
      byte[] context = new byte[length];
      Arrays.fill(context, (byte) length);
      byte[] originalContext = context.clone();
      byte[] master = MASTER.clone();
      master[63] ^= (byte) (length + 1);
      byte[] originalMaster = master.clone();
      byte[] previous = workspace.clone();
      simulator.reset();
      Assertions.assertArrayEquals(previous, workspace);
      if (block != null) {
        Assertions.assertArrayEquals(new byte[block.length], block);
      }
      Assertions.assertArrayEquals(
        deriveReference(master, context),
        derivation.derive(master, context).getKey()
      );
      Assertions.assertSame(workspace, field.get(derivation));
      Assertions.assertSame(block, blockField.get(null));
      Assertions.assertArrayEquals(originalMaster, master);
      Assertions.assertArrayEquals(originalContext, context);
      Assertions.assertArrayEquals(first, derivation.derive(MASTER, CONTEXT).getKey());
    }
  }

  @Test
  public void rejectsZeroAndCandidatesAtOrAboveTheOrder() throws Exception {
    byte[] largest = new byte[32];
    Arrays.fill(largest, (byte) 0xFF);
    byte[] lastScalar = CurveSECP256r1.R.clone();
    lastScalar[31]--;

    CandidateSignature signature = useCandidates(
      new byte[][] { new byte[32], CurveSECP256r1.R.clone(), largest, lastScalar }
    );

    Assertions.assertArrayEquals(
      lastScalar,
      derivation.derive(MASTER.clone(), CONTEXT.clone()).getKey()
    );
    Assertions.assertEquals(4, signature.calls);
  }

  @Test
  public void acceptsTheSmallestScalar() throws Exception {
    byte[] one = new byte[32];
    one[31] = 1;
    CandidateSignature signature = useCandidates(new byte[][] { one });

    Assertions.assertArrayEquals(one, derivation.derive(MASTER.clone(), CONTEXT.clone()).getKey());
    Assertions.assertEquals(1, signature.calls);
  }

  @Test
  public void acceptsTheFinalRetry() throws Exception {
    byte[][] candidates = new byte[256][32];
    candidates[255][31] = 1;
    CandidateSignature signature = useCandidates(candidates);

    Assertions.assertArrayEquals(
      candidates[255],
      derivation.derive(MASTER.clone(), CONTEXT.clone()).getKey()
    );
    Assertions.assertEquals(256, signature.calls);
  }

  @Test
  public void exhaustedRetriesFailWithoutWrappingOrChangingInputs() throws Exception {
    CandidateSignature signature = useCandidates(new byte[256][32]);
    byte[] master = MASTER.clone();
    byte[] context = CONTEXT.clone();
    CryptoException exception = Assertions.assertThrows(CryptoException.class, () ->
      derivation.derive(master, context).getKey()
    );

    Assertions.assertEquals(CryptoException.ILLEGAL_USE, exception.getReason());
    Assertions.assertEquals(256, signature.calls);
    Assertions.assertArrayEquals(MASTER, master);
    Assertions.assertArrayEquals(CONTEXT, context);
    byte[] one = new byte[32];
    one[31] = 1;
    useCandidates(new byte[][] { one });
    Assertions.assertArrayEquals(one, derivation.derive(master, context).getKey());
  }

  private void checkVectors() throws Exception {
    Assertions.assertArrayEquals(
      "monoid-001".getBytes(StandardCharsets.US_ASCII),
      Monoid001Derivation.NAME
    );
    Assertions.assertArrayEquals(
      "Monoid-001".getBytes(StandardCharsets.US_ASCII),
      Monoid001Derivation.MASTER_KEY_LABEL
    );
    Assertions.assertEquals(64, Monoid001Derivation.MASTER_LENGTH);

    Mac extract = Mac.getInstance("HmacSHA512");
    extract.init(new SecretKeySpec("Monoid-001".getBytes(StandardCharsets.US_ASCII), "HmacSHA512"));
    Assertions.assertArrayEquals(
      MASTER,
      extract.doFinal(Hex.decode("000102030405060708090a0b0c0d0e0f"))
    );

    // Generated independently with Node crypto.hkdfSync('sha512', seed, salt, info, 32).
    String[][] vectors = {
      { "", "c3e4135ae1bc8d91eda2766846f658fc511ae4d3414387338532b0a5139017f6" },
      {
        "706173736b65792e6578616d706c652f63726564656e7469616c",
        "46bc496b40ca13a1e2285d40b35ec701fc318e5c64f78065be65c9eff3d6a57c",
      },
      { "007f80ff0001", "0a254ac6c15b3fd9730cf6ba7741f6dbddd53d32b7c0a282a3c13887283b9f67" },
    };

    for (String[] vector : vectors) {
      byte[] master = MASTER.clone();
      byte[] context = Hex.decode(vector[0]);
      byte[] originalContext = context.clone();
      byte[] expected = Hex.decode(vector[1]);

      Assertions.assertArrayEquals(expected, deriveReference(master, context));
      Assertions.assertArrayEquals(expected, derivation.derive(master, context).getKey());
      Assertions.assertArrayEquals(expected, derivation.derive(master, context).getKey());
      Assertions.assertArrayEquals(MASTER, master);
      Assertions.assertArrayEquals(originalContext, context);
    }

    byte[] changedMaster = MASTER.clone();
    changedMaster[63] ^= 1;
    byte[] expected = deriveReference(changedMaster, CONTEXT);

    Assertions.assertFalse(Arrays.equals(deriveReference(MASTER, CONTEXT), expected));
    Assertions.assertArrayEquals(
      expected,
      derivation.derive(changedMaster, CONTEXT.clone()).getKey()
    );
  }

  private static byte[] deriveReference(byte[] master, byte[] context) throws Exception {
    Mac expand = Mac.getInstance("HmacSHA512");
    expand.init(new SecretKeySpec(master, "HmacSHA512"));
    BigInteger order = new BigInteger(1, CurveSECP256r1.R);

    for (int retry = 0; retry <= 255; retry++) {
      expand.update("Monoid-001".getBytes(StandardCharsets.US_ASCII));
      expand.update((byte) 0);
      expand.update(context);
      expand.update((byte) retry);
      byte[] candidate = Arrays.copyOf(expand.doFinal(new byte[] { 1 }), 32);
      BigInteger scalar = new BigInteger(1, candidate);

      if (scalar.signum() > 0 && scalar.compareTo(order) < 0) {
        return candidate;
      }
    }

    throw new AssertionError("No scalar after 256 attempts");
  }

  private static CandidateSignature useCandidates(byte[][] candidates) throws Exception {
    CandidateSignature signature = new CandidateSignature(candidates);
    Field field = LibHMACSha512.class.getDeclaredField("sharedSignature");
    field.setAccessible(true);
    field.set(null, signature);

    return signature;
  }

  private static class CandidateSignature extends SymmetricSignatureImpl {

    private final byte[][] candidates;
    private final ByteArrayOutputStream input = new ByteArrayOutputStream();
    private int calls;

    CandidateSignature(byte[][] candidates) {
      super(Signature.ALG_HMAC_SHA_512);
      this.candidates = candidates;
    }

    @Override
    public void update(byte[] data, short offset, short length) {
      input.write(data, offset, length);
    }

    @Override
    public short sign(byte[] in, short inOffset, short inLength, byte[] out, short outOffset) {
      Assertions.assertTrue(calls < candidates.length, "Candidate counter wrapped or overran");
      byte[] expected = Hex.decode("4d6f6e6f69642d30303100007f80ff00010001");
      expected[expected.length - 2] = (byte) calls;
      input.write(in, inOffset, inLength);
      Assertions.assertArrayEquals(expected, input.toByteArray());
      input.reset();

      Arrays.fill(out, outOffset, outOffset + 64, (byte) 0xA5);
      System.arraycopy(candidates[calls], 0, out, outOffset, 32);
      calls++;

      return 64;
    }
  }
}
