package tests;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.nio.charset.StandardCharsets;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoidsafe.MonoidSafeApplet;
import monoidsafeidentity.MonoidSafeIdentityApplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ShareableSimulatorRuntimeTest {

  private static final AID IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_IDENTITY_AID}}"
    "f06d6f6e6f696400010000"
  );
  private static final AID SAFE_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_AID}}"
    "f06d6f6e6f696401010000"
  );
  private static final AID CALLER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID_WITHOUT_VERSION}}0001"
    "f06d6f6e6f696402010001"
  );

  @Test
  public void dataCallbacksRestoreBothContextsAcrossNestedSafeCalls() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    CardSimulator simulator = new CardSimulator(new ShareableSimulatorRuntime());
    simulator.installApplet(IDENTITY_AID, MonoidSafeIdentityApplet.class);
    simulator.installApplet(SAFE_AID, MonoidSafeApplet.class);
    simulator.installApplet(CALLER_AID, SafeCallerApplet.class);

    try {
      Assertions.assertTrue(simulator.selectApplet(CALLER_AID));
      transmit(simulator, SafeCallerApplet.GET_SHAREABLE, new byte[0]);
      byte[] pin = "314159".getBytes(StandardCharsets.US_ASCII);
      transmit(simulator, SafeCallerApplet.UPDATE_PIN, pin);
      Assertions.assertArrayEquals(
        new byte[] { 1 },
        transmit(simulator, SafeCallerApplet.CHECK_PIN, pin)
      );

      byte[] data = { 1, 2, 3 };
      byte[] calls = transmit(simulator, SafeCallerApplet.VERIFY_DATA_CALLBACK, data);
      Assertions.assertEquals(1, calls.length);
      Assertions.assertTrue(calls[0] >= 2);
      Assertions.assertArrayEquals(
        data,
        transmit(simulator, SafeCallerApplet.GET_DATA, new byte[0])
      );
      Assertions.assertArrayEquals(
        new byte[] { 1 },
        transmit(simulator, SafeCallerApplet.IS_PIN_VALIDATED, new byte[0])
      );
    } finally {
      simulator.deleteApplet(CALLER_AID);
      simulator.deleteApplet(SAFE_AID);
      simulator.deleteApplet(IDENTITY_AID);
    }
  }

  private byte[] transmit(CardSimulator simulator, int instruction, byte[] data) {
    ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(0, instruction, 0, 0, data));
    Assertions.assertEquals(0x9000, response.getSW());
    return response.getData();
  }
}
