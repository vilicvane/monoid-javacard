package tests;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Proxy;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoid.MonoidApplet;
import monoid.Safe;
import monoid.SafeDataSource;
import monoid.SafeItem;
import monoid.SafeItemIterator;
import monoididentity.IdentityShareable;
import monoididentity.MonoidIdentityApplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ShareableSimulatorRuntimeTest {

  private static final AID IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_IDENTITY_AID}}"
    "f06d6f6e6f69640001"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );
  private static final AID CALLER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_NAMESPACE}}7f11"
    "f06d6f6e6f69647f11"
  );

  @Test
  public void processExceptionClearsTransactionDepthBeforeTheNextCommand() {
    ShareableSimulatorRuntime runtime = new ShareableSimulatorRuntime();
    CardSimulator simulator = new CardSimulator(runtime);
    simulator.installApplet(CALLER_AID, TransactionExitApplet.class);

    try {
      Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
      ResponseAPDU failed = simulator.transmitCommand(new CommandAPDU(0, 1, 0, 0));
      Assertions.assertEquals(0x9000, failed.getSW());
      Assertions.assertEquals(0, runtime.getTransactionDepth());

      ResponseAPDU next = simulator.transmitCommand(new CommandAPDU(0, 2, 0, 0, 1));
      Assertions.assertEquals(0x9000, next.getSW());
      Assertions.assertArrayEquals(new byte[] { 0 }, next.getData());
    } finally {
      simulator.deleteApplet(CALLER_AID);
    }
  }

  @Test
  public void identityCallsRestoreTheCallerContext() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    ShareableSimulatorRuntime runtime = new ShareableSimulatorRuntime();
    CardSimulator simulator = new CardSimulator(runtime);
    simulator.installApplet(IDENTITY_AID, MonoidIdentityApplet.class);
    simulator.installApplet(CALLER_AID, IdentityCallerApplet.class);

    try {
      Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
      AID caller = JCSystem.getAID();
      AID previous = JCSystem.getPreviousContextAID();
      IdentityShareable identity = (IdentityShareable) runtime.getSharedObject(
        IDENTITY_AID,
        (byte) 0
      );
      Assertions.assertSame(caller, JCSystem.getAID());
      Assertions.assertSame(previous, JCSystem.getPreviousContextAID());
      Assertions.assertEquals(4, identity.getId().length);
      Assertions.assertEquals(65, identity.getPublicKey().length);
      Assertions.assertSame(caller, JCSystem.getAID());
      Assertions.assertSame(previous, JCSystem.getPreviousContextAID());
    } finally {
      simulator.deleteApplet(CALLER_AID);
      simulator.deleteApplet(IDENTITY_AID);
    }
  }

  @Test
  public void returnedShareablesUnwrapOnlyWhenPassedToTheirOwningContext() {
    ShareableSimulatorRuntime runtime = new ShareableSimulatorRuntime();
    CardSimulator simulator = new CardSimulator(runtime);
    simulator.installApplet(IDENTITY_AID, MonoidIdentityApplet.class);
    simulator.installApplet(CALLER_AID, RoundTripApplet.class);

    try {
      Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
      Shareable foreign = runtime.getSharedObject(IDENTITY_AID, (byte) 0);
      RoundTrip own = (RoundTrip) runtime.getSharedObject(CALLER_AID, (byte) 0);
      Assertions.assertTrue(own.isSelf(own));
      Assertions.assertFalse(own.isProxy(own));
      Assertions.assertTrue(own.isProxy(foreign));
    } finally {
      simulator.deleteApplet(CALLER_AID);
      simulator.deleteApplet(IDENTITY_AID);
    }
  }

  @Test
  public void monoidDoesNotPublishTheInternalSafeAsShareableObjects() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    ShareableSimulatorRuntime runtime = new ShareableSimulatorRuntime();
    CardSimulator simulator = new CardSimulator(runtime);
    simulator.installApplet(IDENTITY_AID, MonoidIdentityApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    simulator.installApplet(CALLER_AID, IdentityCallerApplet.class);

    try {
      Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
      Shareable shared = runtime.getSharedObject(MONOID_AID, (byte) 0);
      Assertions.assertNull(shared);

      for (Class<?> internal : new Class<?>[] {
        Safe.class,
        SafeItem.class,
        SafeItemIterator.class,
        SafeDataSource.class,
      }) {
        Assertions.assertFalse(Shareable.class.isAssignableFrom(internal));
      }
    } finally {
      simulator.deleteApplet(CALLER_AID);
      simulator.deleteApplet(MONOID_AID);
      simulator.deleteApplet(IDENTITY_AID);
    }
  }

  public interface RoundTrip extends Shareable {
    boolean isSelf(Shareable value);

    boolean isProxy(Shareable value);
  }

  public static final class RoundTripApplet extends Applet implements RoundTrip {

    public static void install(byte[] buffer, short offset, byte length) {
      new RoundTripApplet().register();
    }

    @Override
    public void process(APDU apdu) {}

    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
      return this;
    }

    @Override
    public boolean isSelf(Shareable value) {
      return value == this;
    }

    @Override
    public boolean isProxy(Shareable value) {
      return Proxy.isProxyClass(value.getClass());
    }
  }

  public static final class TransactionExitApplet extends Applet {

    public static void install(byte[] buffer, short offset, byte length) {
      new TransactionExitApplet().register();
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        return;
      }

      byte[] buffer = apdu.getBuffer();
      if (buffer[ISO7816.OFFSET_INS] == 1) {
        // No persistent writes: this test covers transaction lifetime, not rollback.
        JCSystem.beginTransaction();
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
      }

      buffer[0] = JCSystem.getTransactionDepth();
      apdu.setOutgoingAndSend((short) 0, (short) 1);
    }
  }
}
