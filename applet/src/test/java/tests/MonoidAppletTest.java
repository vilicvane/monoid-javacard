package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import javacard.framework.AID;
import monoid.MonoidApplet;
import monoid.MonoidException;
import monoidsafe.MonoidSafeApplet;

import org.junit.jupiter.api.*;

import com.licel.jcardsim.utils.AIDUtil;

import java.util.HashMap;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class MonoidAppletTest extends AppletTest {
  private static final AID MONOID_SAFE_AID = AIDUtil.create("F16D6F6E6F696400010000");
  private static final AID MONOID_AID = AIDUtil.create("F16D6F6E6F696401010000");

  private static final byte[] SAFE_PIN = "888888".getBytes();
  private static final byte[] PIN = "123456".getBytes();

  public MonoidAppletTest() {
    super(
        MONOID_AID,
        System.getenv("CARD_TYPE") != null && System.getenv("CARD_TYPE").equals("physical")
            ? CardType.PHYSICAL
            : CardType.JCARDSIMLOCAL);

    if (simulator != null) {
      simulator.installApplet(MONOID_SAFE_AID, MonoidSafeApplet.class);
      simulator.installApplet(MONOID_AID, MonoidApplet.class);
    }
  }

  public static void main(String[] args) throws Exception {
    new MonoidAppletTest().hello();
  }

  @Test
  public void test() throws Exception {
    hello();
    setSafePIN();
    setPIN();
    createRandomKeys();
    setGetClear();
  }

  @Test
  @Tag("manual")
  public void hello() throws Exception {
    SimpleCBORWriter cbor = new SimpleCBORWriter();

    cbor.map((short) 0);

    CommandAPDU request = apdu(0x00, 0x20, 0, 0, cbor.getData());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);
  }

  @Test
  @Tag("manual")
  public void setSafePIN() throws Exception {
    SimpleCBORWriter writer = new SimpleCBORWriter();

    writer.map((short) 2);
    {
      writer.text("pin".getBytes());
      writer.text(SAFE_PIN);

      writer.text("safe".getBytes());
      writer.bool(true);
    }

    CommandAPDU request = apdu(0x00, 0x21, 0, 0, writer.getData());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);
  }

  @Test
  @Tag("manual")
  public void setPIN() throws Exception {
    SimpleCBORWriter writer = new SimpleCBORWriter();

    writer.map((short) 2);
    {
      writeAuth(writer, true);

      writer.text("pin".getBytes());
      writer.text(PIN);
    }

    CommandAPDU request = apdu(0x00, 0x21, 0, 0, writer.getData());

    ResponseAPDU response = connect().transmit(request);

    assertNoError(response);
  }

  private HashMap<String, byte[]> typeToKeyIndexMap = new HashMap<>();

  @Test
  @Tag("manual")
  public void createRandomKeys() throws Exception {
    String[] types = { "seed", "master", "key" };

    for (String type : types) {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) (type == "key" ? 3 : 2));
      {
        writeAuth(writer, false);

        writer.text("type".getBytes());
        writer.text(type.getBytes());

        if (type == "key") {
          writer.text("length".getBytes());
          writer.integer((short) 32);
        }
      }

      CommandAPDU request = apdu(0x00, 0x38, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());
      reader.map();
      {
        typeToKeyIndexMap.put(type, reader.requireKey("index".getBytes()).bytes());
      }
    }
  }

  @Test
  @Tag("manual")
  public void setGetClear() throws Exception {
    byte[] index = "some key".getBytes();
    byte[] data = "some data".getBytes();

    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) 3);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(index);

        writer.text("data".getBytes());
        writer.bytes(data);
      }

      CommandAPDU request = apdu(0x00, 0x32, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);
    }

    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) 2);
      {
        writeAuth(writer, true);

        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x31, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);

      SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());
      reader.map();
      {
        Assertions.assertArrayEquals(data, reader.requireKey("data".getBytes()).bytes());
      }
    }

    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) 2);
      {
        writeAuth(writer, false);

        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x33, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertNoError(response);
    }

    {
      SimpleCBORWriter writer = new SimpleCBORWriter();

      writer.map((short) 2);
      {
        writeAuth(writer, true);

        writer.text("index".getBytes());
        writer.bytes(index);
      }

      CommandAPDU request = apdu(0x00, 0x31, 0, 0, writer.getData());

      ResponseAPDU response = connect().transmit(request);

      assertError(response, MonoidException.CODE_NOT_FOUND);
    }
  }

  private void writeAuth(SimpleCBORWriter writer, boolean safeAuth) {
    writer.text("auth".getBytes());
    writer.map((short) (safeAuth ? 2 : 1));
    {
      writer.text("pin".getBytes());
      writer.text(safeAuth ? SAFE_PIN : PIN);

      if (safeAuth) {
        writer.text("safe".getBytes());
        writer.bool(true);
      }
    }
  }

  private void assertNoError(ResponseAPDU response) {
    Assertions.assertEquals(0x9000, response.getSW());

    SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());
    reader.map();
    Assertions.assertFalse(reader.key("error".getBytes()));
  }

  private void assertError(ResponseAPDU response, byte[] code) {
    Assertions.assertEquals(0x9000, response.getSW());

    SimpleCBORReader reader = new SimpleCBORReader(response.getBytes());
    reader.map();
    reader.requireKey("error".getBytes()).map();
    Assertions.assertArrayEquals(code, reader.requireKey("code".getBytes()).text());
  }
}
