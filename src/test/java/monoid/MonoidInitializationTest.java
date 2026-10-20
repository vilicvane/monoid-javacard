package monoid;

import com.licel.jcardsim.base.TransientMemory;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import main.ShareableSimulatorRuntime;
import monoididentity.MonoidIdentityApplet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class MonoidInitializationTest {

  private static final AID IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_IDENTITY_AID}}"
    "f06d6f6e6f69640001"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );
  private static final AID OTHER_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_NAMESPACE}}7f11"
    "f06d6f6e6f69647f11"
  );

  private CountingTransientMemory memory;
  private CardSimulator simulator;
  private AID installedAID;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    MonoidApplet.safe = null;
    MonoidApplet.keystore = null;
    memory = new CountingTransientMemory();
    simulator = new CardSimulator(new ShareableSimulatorRuntime(memory));
    simulator.installApplet(IDENTITY_AID, MonoidIdentityApplet.class);
  }

  @AfterEach
  public void clear() {
    uninstall();
    simulator.deleteApplet(IDENTITY_AID);
  }

  @Test
  public void initializationDoesNotAllocateMoreTransientMemoryForSmallerFragments() {
    install(MONOID_AID);
    assertVersion(transmit(new byte[] { (byte) 0xA0 }, 255));
    byte[] request = paddedRequest();
    int expectedAllocation = allocatedForRequest(request, 255);

    Assertions.assertEquals(expectedAllocation, allocatedForRequest(request, 127));
    Assertions.assertEquals(expectedAllocation, allocatedForRequest(request, 31));
  }

  @Test
  public void reportsTheConfiguredVersionIndependentlyOfTheInstanceAID() {
    for (AID aid : new AID[] { MONOID_AID, OTHER_AID }) {
      install(aid);
      assertVersion(transmit(new byte[] { (byte) 0xA0 }, 255));
      assertVersion(transmit(new byte[] { (byte) 0xA0 }, 255));
      uninstall();
    }
  }

  private int allocatedForRequest(byte[] request, int frameLength) {
    int before = memory.allocatedByteCount;
    byte[] response = transmit(request, frameLength);
    int allocated = memory.allocatedByteCount - before;
    assertVersion(response);
    return allocated;
  }

  private void install(AID aid) {
    installedAID = aid;
    simulator.installApplet(installedAID, MonoidApplet.class);
    Assertions.assertTrue(simulator.selectApplet(installedAID));
  }

  private void uninstall() {
    if (installedAID != null) {
      Assertions.assertTrue(simulator.selectApplet(IDENTITY_AID));
      simulator.deleteApplet(installedAID);
      installedAID = null;
    }
  }

  private byte[] transmit(byte[] request, int frameLength) {
    ResponseAPDU response = null;

    for (int offset = 0; offset < request.length; offset += frameLength) {
      int end = Math.min(offset + frameLength, request.length);
      boolean last = end == request.length;
      int cla = request.length <= frameLength ? 0 : offset == 0 ? 0x90 : last ? 0xA0 : 0xB0;
      response = simulator.transmitCommand(
        new CommandAPDU(cla, 0x20, 0, 0, Arrays.copyOfRange(request, offset, end))
      );
      Assertions.assertEquals(
        0x9000,
        response.getSW(),
        "frame length " + frameLength + ", offset " + offset
      );

      if (!last) {
        Assertions.assertEquals(0, response.getData().length);
      }
    }

    return response.getData();
  }

  private void assertVersion(byte[] data) {
    CBORBufferReader reader = new CBORBufferReader(data);
    reader.map();
    Assertions.assertEquals(Constants.MONOID_VERSION, reader.requireKey(Text.version).integer());
  }

  private byte[] paddedRequest() {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    output.write(0xA1);
    output.write(0x61);
    output.write('x');
    output.write(0x59);
    output.write(0x18);
    output.write(0x01);
    output.write(new byte[6145], 0, 6145);
    return output.toByteArray();
  }

  private static class CountingTransientMemory extends TransientMemory {

    int allocatedByteCount;

    @Override
    public byte[] makeByteArray(int length, byte event) {
      allocatedByteCount += length;
      return super.makeByteArray(length, event);
    }
  }
}
