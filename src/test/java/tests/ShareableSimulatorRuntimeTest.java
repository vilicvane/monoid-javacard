package tests;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import main.ShareableSimulatorRuntime;
import monoid.Monoid;
import monoid.MonoidApplet;
import monoid.Safe;
import monoid.SafeDataSource;
import monoid.SafeItem;
import monoid.SafeItemIterator;
import monoidsafeidentity.MonoidSafeIdentityApplet;
import monoidsafeidentity.SafeIdentityShareable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ShareableSimulatorRuntimeTest {

  private static final AID IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_IDENTITY_AID}}"
    "f06d6f6e6f696400010000"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f696402010000"
  );
  private static final AID CALLER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID_WITHOUT_VERSION}}0001"
    "f06d6f6e6f696402010001"
  );

  @Test
  public void identityCallsRestoreTheCallerContext() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    ShareableSimulatorRuntime runtime = new ShareableSimulatorRuntime();
    CardSimulator simulator = new CardSimulator(runtime);
    simulator.installApplet(IDENTITY_AID, MonoidSafeIdentityApplet.class);
    simulator.installApplet(CALLER_AID, IdentityCallerApplet.class);

    try {
      Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
      AID caller = JCSystem.getAID();
      AID previous = JCSystem.getPreviousContextAID();
      SafeIdentityShareable identity = (SafeIdentityShareable) runtime.getSharedObject(
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
  public void monoidDoesNotPublishTheInternalSafeAsShareableObjects() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    ShareableSimulatorRuntime runtime = new ShareableSimulatorRuntime();
    CardSimulator simulator = new CardSimulator(runtime);
    simulator.installApplet(IDENTITY_AID, MonoidSafeIdentityApplet.class);
    simulator.installApplet(MONOID_AID, MonoidApplet.class);
    simulator.installApplet(CALLER_AID, IdentityCallerApplet.class);

    try {
      Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
      Shareable shared = runtime.getSharedObject(MONOID_AID, (byte) 0);
      Assertions.assertInstanceOf(Monoid.class, shared);
      Assertions.assertEquals(0, Monoid.class.getMethods().length);

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
}
