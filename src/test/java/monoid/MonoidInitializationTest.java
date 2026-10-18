package monoid;

import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.base.TransientMemory;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoidsafe.MonoidSafeApplet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class MonoidInitializationTest {

  private static final AID SAFE_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_SAFE_AID}}"
    "f06d6f6e6f696401010000"
  );
  private static final String MONOID_AID =
    // @inplate-line "{{hex MONOID_AID}}";
    "f06d6f6e6f696402010000";

  private CountingTransientMemory memory;
  private CardSimulator simulator;
  private AID installedAID;

  @BeforeEach
  public void initialize() {
    System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
    MonoidApplet.safe = null;
    MonoidApplet.safePIN = null;
    MonoidApplet.keystore = null;
    memory = new CountingTransientMemory();
    simulator = new CardSimulator(new SimulatorRuntime(memory));
    simulator.installApplet(SAFE_AID, MonoidSafeApplet.class);
  }

  @AfterEach
  public void clear() {
    uninstall();
    simulator.deleteApplet(SAFE_AID);
  }

  @Test
  public void zeroVersionDoesNotAllocateMoreTransientMemoryForSmallerFragments() {
    install(0);
    assertVersion(transmit(new byte[] { (byte) 0xA0 }, 255), 0);
    byte[] request = paddedRequest();
    int expectedAllocation = allocatedForRequest(request, 255);

    Assertions.assertEquals(expectedAllocation, allocatedForRequest(request, 127));
    Assertions.assertEquals(expectedAllocation, allocatedForRequest(request, 31));
  }

  @Test
  public void reportsEveryVersionAfterReinstallingTheApplet() {
    for (int version : new int[] { 0x1234, 0x8001, 0xFFFF, 0, 1 }) {
      install(version);
      assertVersion(transmit(new byte[] { (byte) 0xA0 }, 255), version);
      assertVersion(transmit(new byte[] { (byte) 0xA0 }, 255), version);
      uninstall();
    }
  }

  private int allocatedForRequest(byte[] request, int frameLength) {
    int before = memory.allocatedByteCount;
    byte[] response = transmit(request, frameLength);
    int allocated = memory.allocatedByteCount - before;
    assertVersion(response, 0);
    return allocated;
  }

  private void install(int version) {
    installedAID = AIDUtil.create(
      MONOID_AID.substring(0, MONOID_AID.length() - 4) + String.format("%04x", version)
    );
    simulator.installApplet(installedAID, MonoidApplet.class);
    Assertions.assertTrue(simulator.selectApplet(installedAID));
  }

  private void uninstall() {
    if (installedAID != null) {
      Assertions.assertTrue(simulator.selectApplet(SAFE_AID));
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

  private void assertVersion(byte[] data, int expected) {
    CBORBufferReader reader = new CBORBufferReader(data);
    reader.map();
    Assertions.assertEquals((short) expected, reader.requireKey(Text.version).integer());
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
