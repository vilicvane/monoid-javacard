package monoidotp;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import monoid.Monoid;
import monoid.MonoidClientShareable;

public final class MonoidOTPApplet extends Applet implements AppletEvent, MonoidClientShareable {

  private static byte[] token;
  private static byte[] tokenHash;
  private static Object[] pending;
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

    pending = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
    Command.init();
    transport = new ApduTransport(Command.reader, Command.writer);

    new MonoidOTPApplet().register();
  }

  @Override
  public void uninstall() {
    Command.dispose();
    token = null;
    tokenHash = null;
    pending = null;
    transport = null;
  }

  @Override
  public void process(APDU apdu) {
    if (selectingApplet()) {
      transport.clear();
      return;
    }

    transport.process(apdu);
  }

  @Override
  public void deselect() {
    super.deselect();
    transport.clear();
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
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    Util.arrayCopyNonAtomic(tokenHash, (short) 0, dest, offset, (short) tokenHash.length);
    return (short) tokenHash.length;
  }

  static Monoid connect() {
    AID aid = JCSystem.lookupAID(
      Constants.MONOID_AID,
      (short) 0,
      (byte) Constants.MONOID_AID.length
    );

    if (aid == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    Monoid monoid = (Monoid) JCSystem.getAppletShareableInterfaceObject(aid, (byte) 1);

    if (monoid == null) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    byte[] buffer = APDU.getCurrentAPDUBuffer();
    Util.arrayCopyNonAtomic(token, (short) 0, buffer, (short) 0, (short) token.length);
    monoid.authenticate(buffer, (short) 0);
    return monoid;
  }

  static void setBatch(OTPBatch batch) {
    pending[0] = batch;
  }

  static OTPBatch takeBatch() {
    OTPBatch batch = (OTPBatch) pending[0];
    pending[0] = null;
    return batch;
  }
}
