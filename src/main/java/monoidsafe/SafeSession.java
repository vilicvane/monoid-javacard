package monoidsafe;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public class SafeSession implements SafeShareable {

  private static final short AUTH_SAFE = (short) 0x5AFE;

  private final MonoidSafeApplet applet;
  private final AID caller;

  // SIO calls run with the client selected, so Safe-owned state must use CLEAR_ON_RESET.
  private final short[] auth = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);
  private final Object[] next = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );

  public SafeSession(MonoidSafeApplet applet, AID caller) {
    this.applet = applet;
    this.caller = caller;
  }

  @Override
  public byte[] getId() {
    assertCaller();
    return applet.getId();
  }

  @Override
  public boolean isPINSet() {
    assertCaller();
    return applet.isPINSet();
  }

  @Override
  public byte getPINTriesRemaining() {
    assertCaller();
    return applet.getPINTriesRemaining();
  }

  @Override
  public boolean checkPIN(byte[] buffer, short offset, byte length) {
    return applet.checkPIN(this, buffer, offset, length);
  }

  @Override
  public void updatePIN(byte[] buffer, short offset, byte length) {
    applet.updatePIN(this, buffer, offset, length);
  }

  @Override
  public boolean isPINValidated() {
    return applet.isPINValidated(this);
  }

  @Override
  public Object[] list(short type) {
    return applet.list(this, type);
  }

  @Override
  public SafeItemShareable get(byte[] index) {
    return applet.get(this, index);
  }

  @Override
  public SafeItemShareable create(byte[] index, byte[] alias, byte[] data) {
    return applet.create(this, index, alias, data);
  }

  boolean matches(AID caller) {
    return this.caller == caller;
  }

  SafeSession getNext() {
    return (SafeSession) next[0];
  }

  void setNext(SafeSession session) {
    next[0] = session;
  }

  void setAuth() {
    auth[0] = 0;
    auth[1] = (short) ~AUTH_SAFE;
    auth[0] = AUTH_SAFE;
  }

  void clearAuth() {
    auth[0] = 0;
    auth[1] = 0;
  }

  boolean isAuthorized() {
    if (auth[0] == 0 && auth[1] == 0) {
      return false;
    }

    if (auth[0] != AUTH_SAFE || auth[1] != (short) ~AUTH_SAFE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    return true;
  }

  void assertCaller() {
    if (caller == null || JCSystem.getPreviousContextAID() != caller) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  void assertAccess() {
    applet.assertAccess(this);
  }

  void remove(SafeItem item) {
    applet.remove(this, item);
  }
}
