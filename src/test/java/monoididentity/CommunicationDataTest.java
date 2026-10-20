package monoididentity;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import main.ShareableSimulatorRuntime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CommunicationDataTest {

  private AID caller;
  private CallerRuntime runtime;
  private CardSimulator simulator;
  private CommunicationData result;

  @BeforeEach
  public void initialize() {
    runtime = new CallerRuntime();
    caller = AIDUtil.create("f06d000001");
    runtime.caller = caller;
    runtime.other = AIDUtil.create("f06d000002");
    simulator = new CardSimulator(runtime);
    result = new CommunicationData(new byte[] { 1, 2, 3, 4 }, caller);
  }

  @Test
  public void everyFreshCallerReadMustMatchBeforeLengthOrBytesAreReturned() {
    for (int failure = 1; failure <= 3; failure++) {
      runtime.expect(failure);
      ISOException exception = Assertions.assertThrows(ISOException.class, result::getLength);
      Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
      Assertions.assertEquals(failure, runtime.reads);

      byte[] destination = new byte[4];
      Arrays.fill(destination, (byte) 0x7E);
      byte[] untouched = destination.clone();
      runtime.expect(failure);
      exception = Assertions.assertThrows(ISOException.class, () ->
        result.read((short) 0, destination, (short) 0, (short) destination.length)
      );
      Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
      Assertions.assertEquals(failure, runtime.reads);
      Assertions.assertArrayEquals(untouched, destination);
    }
  }

  @Test
  public void oneSpuriousCallerMatchCannotReleaseLengthOrBytes() {
    runtime.caller = AIDUtil.create("f06d000002");
    runtime.other = caller;

    for (int faultedRound = 1; faultedRound <= 3; faultedRound++) {
      int expectedReads = faultedRound == 1 ? 2 : 1;
      runtime.expect(faultedRound);
      ISOException exception = Assertions.assertThrows(ISOException.class, result::getLength);
      Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
      Assertions.assertEquals(expectedReads, runtime.reads);

      byte[] destination = new byte[4];
      Arrays.fill(destination, (byte) 0x7E);
      byte[] untouched = destination.clone();
      runtime.expect(faultedRound);
      exception = Assertions.assertThrows(ISOException.class, () ->
        result.read((short) 0, destination, (short) 0, (short) destination.length)
      );
      Assertions.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, exception.getReason());
      Assertions.assertEquals(expectedReads, runtime.reads);
      Assertions.assertArrayEquals(untouched, destination);
    }
  }

  @Test
  public void repeatedReadsSucceedOnlyAfterThreeFreshCallerConfirmations() {
    runtime.expect(0);
    Assertions.assertEquals(4, result.getLength());
    Assertions.assertEquals(3, runtime.reads);

    byte[] destination = new byte[4];
    runtime.expect(0);
    result.read((short) 0, destination, (short) 0, (short) destination.length);
    Assertions.assertArrayEquals(new byte[] { 1, 2, 3, 4 }, destination);
    Assertions.assertEquals(3, runtime.reads);
  }

  private static final class CallerRuntime extends ShareableSimulatorRuntime {

    private AID caller;
    private AID other;
    private int failAt;
    private int reads;

    void expect(int failAt) {
      this.failAt = failAt;
      reads = 0;
    }

    @Override
    public AID getPreviousContextAID() {
      reads++;
      return reads == failAt ? other : caller;
    }
  }
}
