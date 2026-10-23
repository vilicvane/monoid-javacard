package monoidsecuritykey;

import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javax.smartcardio.CommandAPDU;
import monoid.Monoid;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AuthenticatorScopeTest {

  private static final String APPLET = "f06d6f6e6f69647a01";
  private CardSimulator simulator;
  private Authenticator authenticator;
  private DelegatedKey delegated;

  @BeforeEach
  public void initialize() {
    simulator = new CardSimulator();
    simulator.installApplet(AIDUtil.create(APPLET), ScopeApplet.class);
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET)));
    authenticator = new Authenticator();
    delegated = new DelegatedKey();
  }

  @Test
  public void scopeHashesTheDelegatedPointUsingADistinctFixedLengthContext() throws Exception {
    byte[] expected = MessageDigest.getInstance("SHA-256").digest(delegated.point);

    run(() -> authenticator.selectScope(delegated.service));

    byte[] label = "monoid fido2 scope: ".getBytes(StandardCharsets.UTF_8);
    byte[] context = Arrays.copyOf(label, 78);
    Assertions.assertArrayEquals(context, delegated.contexts.get(0));
    Assertions.assertArrayEquals(expected, authenticator.credentials.scope);

    Arrays.fill(delegated.point, (byte) 0);
    Assertions.assertArrayEquals(expected, authenticator.credentials.scope);
  }

  @Test
  public void everySelectionObservesTheCurrentDelegatedPointIncludingAfterReset() throws Exception {
    byte[] original = MessageDigest.getInstance("SHA-256").digest(delegated.point);

    run(() -> authenticator.selectScope(delegated.service));
    run(() -> authenticator.selectScope(delegated.service));

    Assertions.assertArrayEquals(original, authenticator.credentials.scope);
    Assertions.assertEquals(2, delegated.contexts.size());

    // Model a new point returned by the same SIO after its seed or domain changes.
    delegated.point = point(2);
    byte[] changed = MessageDigest.getInstance("SHA-256").digest(delegated.point);
    run(() -> authenticator.selectScope(delegated.service));

    Assertions.assertArrayEquals(changed, authenticator.credentials.scope);
    Assertions.assertFalse(Arrays.equals(original, changed));

    simulator.reset();
    Assertions.assertTrue(simulator.selectApplet(AIDUtil.create(APPLET)));
    delegated.point = point(1);
    run(() -> authenticator.selectScope(delegated.service));

    Assertions.assertArrayEquals(original, authenticator.credentials.scope);
    Assertions.assertEquals(4, delegated.contexts.size());
  }

  @Test
  public void failedDelegationDoesNotPublishAPartialScope() {
    run(() -> authenticator.selectScope(delegated.service));
    byte[] original = authenticator.credentials.scope.clone();
    delegated.failure = (short) 0x6982;

    ISOException exception = Assertions.assertThrows(ISOException.class, () ->
      run(() -> authenticator.selectScope(delegated.service))
    );

    Assertions.assertEquals((short) 0x6982, exception.getReason());
    Assertions.assertArrayEquals(original, authenticator.credentials.scope);
  }

  private static byte[] point(int scalar) {
    return SECNamedCurves.getByName("secp256r1")
      .getG()
      .multiply(BigInteger.valueOf(scalar))
      .getEncoded(false);
  }

  private void run(Runnable operation) {
    ScopeApplet.operation = operation;
    ScopeApplet.failure = null;

    try {
      Assertions.assertEquals(
        0x9000,
        simulator.transmitCommand(new CommandAPDU(0, 1, 0, 0)).getSW()
      );

      if (ScopeApplet.failure instanceof RuntimeException) {
        throw (RuntimeException) ScopeApplet.failure;
      }

      if (ScopeApplet.failure != null) {
        throw (Error) ScopeApplet.failure;
      }
    } finally {
      ScopeApplet.operation = null;
      ScopeApplet.failure = null;
    }
  }

  public static final class ScopeApplet extends Applet {

    private static Runnable operation;
    private static Throwable failure;

    public static void install(byte[] buffer, short offset, byte length) {
      new ScopeApplet().register();
    }

    @Override
    public void process(APDU apdu) {
      if (!selectingApplet()) {
        try {
          operation.run();
        } catch (RuntimeException | Error exception) {
          failure = exception;
        }
      }
    }
  }

  /** The SIO is mocked; these checks cover scope framing and hashing, not seed derivation. */
  private static final class DelegatedKey {

    byte[] point = point(1);
    short failure;
    final List<byte[]> contexts = new ArrayList<>();
    final Monoid service = (Monoid) Proxy.newProxyInstance(
      Monoid.class.getClassLoader(),
      new Class<?>[] { Monoid.class },
      (proxy, method, arguments) -> {
        if (!method.getName().equals("getMonoid001PublicKey") || arguments.length != 5) {
          throw new UnsupportedOperationException(method.getName());
        }

        byte[] source = (byte[]) arguments[0];
        short offset = (short) arguments[1];
        short length = (short) arguments[2];
        contexts.add(Arrays.copyOfRange(source, offset, offset + length));

        if (failure != 0) {
          ISOException.throwIt(failure);
        }

        System.arraycopy(point, 0, (byte[]) arguments[3], (short) arguments[4], point.length);
        return (short) point.length;
      }
    );
  }
}
