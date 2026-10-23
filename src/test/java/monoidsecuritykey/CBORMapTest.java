package monoidsecuritykey;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Field;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.JCSystem;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoidlib.CBORMap;
import monoidlib.CBORReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CBORMapTest {

  @Test
  public void nestedIntegerAndTextIndexesRemainIndependentAndClearOnDeselect() throws Exception {
    CardSimulator simulator = new CardSimulator();
    AID aid = AIDUtil.create("f06d6f6e6f69647c01");
    AID other = AIDUtil.create("f06d6f6e6f69647c02");
    simulator.installApplet(aid, MapApplet.class);
    simulator.installApplet(other, EmptyApplet.class);
    Assertions.assertTrue(simulator.selectApplet(aid));

    try {
      assertValues(simulator, 1);
      short[] outer = offsets(MapApplet.outer);
      short[] inner = offsets(MapApplet.inner);
      Assertions.assertNotSame(outer, inner);
      Assertions.assertEquals(JCSystem.CLEAR_ON_DESELECT, JCSystem.isTransient(outer));
      Assertions.assertEquals(JCSystem.CLEAR_ON_DESELECT, JCSystem.isTransient(inner));
      assertValues(simulator, 2);

      Assertions.assertTrue(simulator.selectApplet(other));
      Assertions.assertArrayEquals(new short[3], outer);
      Assertions.assertArrayEquals(new short[2], inner);
      Assertions.assertTrue(simulator.selectApplet(aid));
      Assertions.assertEquals(
        CTAP.MISSING_PARAMETER,
        simulator.transmitCommand(new CommandAPDU(0, 2, 0, 0)).getSW()
      );
      assertValues(simulator, 1);
    } finally {
      MapApplet.outer = null;
      MapApplet.inner = null;
    }
  }

  private static short[] offsets(CBORMap map) throws Exception {
    Field field = CBORMap.class.getDeclaredField("offsets");
    field.setAccessible(true);
    return (short[]) field.get(map);
  }

  private static void assertValues(CardSimulator simulator, int command) {
    ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(0, command, 0, 0));
    Assertions.assertEquals(0x9000, response.getSW());
    Assertions.assertArrayEquals(new byte[] { 3, 1, 2 }, response.getData());
  }

  public static final class MapApplet extends Applet {

    private static final byte[] A = { 'a' };
    private static final byte[] B = { 'b' };
    private static final byte[] INPUT = {
      (byte) 0xa2,
      1,
      (byte) 0xa2,
      0x61,
      'a',
      1,
      0x61,
      'b',
      2,
      2,
      3,
    };
    // Keep the maps only in this fixture to observe the JCRE deselection lifecycle.
    private static CBORMap outer;
    private static CBORMap inner;

    public static void install(byte[] buffer, short offset, byte length) {
      new MapApplet().register();
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        return;
      }
      byte[] buffer = apdu.getBuffer();
      if (buffer[1] == 1) {
        CBORReader reader = new CBORReader(INPUT, (short) 0, (short) INPUT.length);
        outer = reader.map(new short[] { 1, 2, 3 });
        inner = outer.requireKey((short) 1).map(new Object[] { A, B });
      }
      buffer[0] = (byte) outer.requireKey((short) 2).integer();
      buffer[1] = (byte) inner.requireKey(A).integer();
      buffer[2] = (byte) inner.requireKey(B).integer();
      apdu.setOutgoingAndSend((short) 0, (short) 3);
    }
  }

  public static final class EmptyApplet extends Applet {

    public static void install(byte[] buffer, short offset, byte length) {
      new EmptyApplet().register();
    }

    @Override
    public void process(APDU apdu) {}
  }
}
