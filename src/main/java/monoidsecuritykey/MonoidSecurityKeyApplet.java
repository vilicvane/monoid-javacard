package monoidsecuritykey;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.apdu.ExtendedLength;
import monoid.Monoid;
import monoid.MonoidClientShareable;

public final class MonoidSecurityKeyApplet
  extends Applet
  implements AppletEvent, MonoidClientShareable, ExtendedLength {

  private static byte[] token;
  private static byte[] tokenHash;
  private static ApduTransport transport;

  public static void install(byte[] buffer, short offset, byte length) {
    token = new byte[32];
    tokenHash = new byte[32];
    RandomData.getInstance(RandomData.ALG_KEYGENERATION).nextBytes(token, (short) 0, (short) 32);
    MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false).doFinal(
      token,
      (short) 0,
      (short) 32,
      tokenHash,
      (short) 0
    );
    Command.init();
    transport = new ApduTransport();

    // The standard FIDO instance AID differs from the Monoid CAP module AID.
    MonoidSecurityKeyApplet applet = new MonoidSecurityKeyApplet();
    if (buffer[offset] == 0) {
      applet.register();
    } else {
      applet.register(buffer, (short) (offset + 1), buffer[offset]);
    }
  }

  @Override
  public void uninstall() {
    Command.dispose();
    token = null;
    tokenHash = null;
    transport = null;
  }

  @Override
  public void process(APDU apdu) {
    if (selectingApplet()) {
      transport.clear();
      Command.clear();
      apdu.setOutgoing();
      apdu.setOutgoingLength((short) Constants.FIDO_VERSION.length);
      apdu.sendBytesLong(Constants.FIDO_VERSION, (short) 0, (short) Constants.FIDO_VERSION.length);
      return;
    }
    transport.process(apdu);
  }

  @Override
  public void deselect() {
    super.deselect();
    transport.clear();
    Command.clear();
  }

  @Override
  public Shareable getShareableInterfaceObject(AID caller, byte parameter) {
    return parameter == 0 &&
      caller != null &&
      caller.equals(Constants.MONOID_AID, (short) 0, (byte) Constants.MONOID_AID.length)
      ? this
      : null;
  }

  @Override
  public short getTokenHash(byte[] dest, short offset) {
    AID caller = JCSystem.getPreviousContextAID();
    if (
      caller == null ||
      !caller.equals(Constants.MONOID_AID, (short) 0, (byte) Constants.MONOID_AID.length)
    ) {
      ISOException.throwIt((short) 0x6982);
    }
    Util.arrayCopyNonAtomic(tokenHash, (short) 0, dest, offset, (short) 32);
    return 32;
  }

  static Monoid connect() {
    AID aid = JCSystem.lookupAID(
      Constants.MONOID_AID,
      (short) 0,
      (byte) Constants.MONOID_AID.length
    );
    if (aid == null) {
      ISOException.throwIt(CTAP.OPERATION_DENIED);
    }
    Monoid monoid = (Monoid) JCSystem.getAppletShareableInterfaceObject(aid, (byte) 1);
    if (monoid == null) {
      ISOException.throwIt(CTAP.OPERATION_DENIED);
    }
    byte[] buffer = APDU.getCurrentAPDUBuffer();
    Util.arrayCopyNonAtomic(token, (short) 0, buffer, (short) 0, (short) token.length);
    monoid.authenticate(buffer, (short) 0);
    return monoid;
  }
}
