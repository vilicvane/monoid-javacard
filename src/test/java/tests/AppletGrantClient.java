package tests;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import monoid.MonoidClientShareable;
import org.junit.jupiter.api.Assertions;

/** A separately installed client whose token never has an APDU read interface. */
public class AppletGrantClient extends Applet implements MonoidClientShareable {

  static AppletGrantClient installed;

  final byte[] token = new byte[32];
  private final byte[] tokenHash = new byte[32];

  boolean exposesIdentity = true;
  short resultLength = 32;
  Runnable onHash;
  int hashCalls;

  public static void install(byte[] buffer, short offset, byte length) {
    installed = new AppletGrantClient();
    installed.register();
  }

  private AppletGrantClient() {
    RandomData.getInstance(RandomData.ALG_TRNG).nextBytes(token, (short) 0, (short) token.length);
    MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false).doFinal(
      token,
      (short) 0,
      (short) token.length,
      tokenHash,
      (short) 0
    );
  }

  @Override
  public void process(APDU apdu) {
    if (!selectingApplet()) {
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }

  @Override
  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    return exposesIdentity && parameter == 0 ? this : null;
  }

  @Override
  public short getTokenHash(byte[] dest, short offset) {
    Assertions.assertNotNull(JCSystem.getPreviousContextAID());
    Assertions.assertEquals(0, JCSystem.getTransactionDepth());
    hashCalls++;
    Util.arrayCopyNonAtomic(tokenHash, (short) 0, dest, offset, (short) tokenHash.length);

    if (onHash != null) {
      onHash.run();
    }

    return resultLength;
  }

  public static class WrongInterface extends Applet implements Shareable {

    public static void install(byte[] buffer, short offset, byte length) {
      new WrongInterface().register();
    }

    @Override
    public void process(APDU apdu) {}

    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
      return this;
    }
  }
}
