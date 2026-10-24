package tests;

import static tests.MonoidItemTransferTest.fields;

import com.licel.jcardsim.utils.AIDUtil;
import java.util.Map;
import javacard.framework.AID;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import monoid.Monoid;
import monoidlib.Utils;
import org.junit.jupiter.api.Assertions;
import tests.MonoidItemTransferTest.Card;

/** Two independently installed clients for grant and user-authentication boundary tests. */
final class MonoidClientFixture implements AutoCloseable {

  static final AID MONOID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );
  static final AID CLIENT = AIDUtil.create("f0010203040501");
  static final AID OTHER = AIDUtil.create("f0010203040502");
  final Card card = new Card(true);
  final AppletGrantClient client;
  final AppletGrantClient other;

  MonoidClientFixture() {
    card.simulator.installApplet(CLIENT, AppletGrantClient.class);
    client = AppletGrantClient.installed;
    card.simulator.installApplet(OTHER, AppletGrantClient.class);
    other = AppletGrantClient.installed;
    select(MONOID);
    card.authenticate(true);
  }

  void select(AID aid) {
    Assertions.assertTrue(card.simulator.selectApplet(aid));
  }

  void grant(AID aid, Object... permissions) {
    Map<String, Object> request = fields(permissions);
    request.put("aid", AppletTest.aidBytes(aid));
    MonoidAppletGrantTest.success(card, 0x51, request);
  }

  void approve(AID aid) {
    approve(aid, false);
  }

  void approve(AID aid, boolean secret) {
    select(MONOID);
    Map<String, Object> request = fields(
      "pin",
      secret ? "888888" : "123456",
      "aid",
      AppletTest.aidBytes(aid)
    );
    if (secret) {
      request.put("secret", true);
    }
    card.success(0x21, request);
  }

  Monoid connect(AID aid, byte parameter, boolean authenticate) {
    select(aid);
    Monoid session = (Monoid) JCSystem.getAppletShareableInterfaceObject(MONOID, parameter);
    Assertions.assertNotNull(session);
    if (authenticate) {
      session.authenticate(global(aid == CLIENT ? client.token : other.token));
    }
    return session;
  }

  Monoid connect() {
    return connect(CLIENT, (byte) 0, true);
  }

  static byte[] global(byte[] data) {
    return Utils.duplicateAsGlobal(data);
  }

  static byte[] index(int type, int id) {
    byte[] index = new byte[10];
    index[0] = (byte) (type >>> 8);
    index[1] = (byte) type;
    index[9] = (byte) id;
    return index;
  }

  static void assertStatus(int expected, Runnable operation) {
    Assertions.assertEquals(
      expected,
      Assertions.assertThrows(ISOException.class, operation::run).getReason() & 0xFFFF
    );
  }

  @Override
  public void close() {
    card.simulator.deleteApplet(CLIENT);
    card.simulator.deleteApplet(OTHER);
    card.close();
  }
}
