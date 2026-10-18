package monoidsafe;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public class SafeSession implements SafeShareable {

  private static final short AUTH_SAFE = (short) 0x5AFE;

  private final MonoidSafeApplet applet;
  private final AID caller;

  private final LibSecurity.Condition callerValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return caller != null && JCSystem.getPreviousContextAID() == caller;
    }
  };

  // SIO calls run with the client selected, so Safe-owned state must use CLEAR_ON_RESET.
  private final short[] auth = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);
  private final Object[] next = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_RESET
  );

  private final LibSecurity.Condition authorizationValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      if (auth[0] == 0 && auth[1] == 0) {
        return false;
      }

      if (auth[0] != AUTH_SAFE || auth[1] != (short) ~AUTH_SAFE) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }

      return true;
    }
  };

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
  public byte[] getPublicKey() {
    assertCaller();
    return applet.getPublicKey();
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
  public SafeItemIteratorShareable list(short type) {
    return applet.list(this, type);
  }

  @Override
  public SafeItemIteratorShareable list(short type, byte[] keyPrefix) {
    return applet.list(this, type, keyPrefix);
  }

  @Override
  public SafeItemShareable get(byte[] index) {
    return applet.get(this, index);
  }

  @Override
  public SafeItemShareable create(
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] data,
    boolean secret
  ) {
    return applet.create(this, index, key, alias, data, secret);
  }

  @Override
  public void importItem(
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] senderPublicKey,
    byte[] data
  ) {
    applet.importItem(this, index, key, alias, senderPublicKey, data);
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

  short isAuthorized() {
    return LibSecurity.check(authorizationValidation, Constants.SAFE_FALSE);
  }

  void assertCaller() {
    if (LibSecurity.check(callerValidation, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  void assertAccess() {
    applet.assertAccess(this);
  }

  void checkStorage(short length) {
    applet.checkStorage(length);
  }

  void remove(SafeItem item) {
    applet.remove(this, item);
  }

  byte[] exportItem(SafeItem item, byte[] recipientPublicKey) {
    return applet.exportItem(this, item, recipientPublicKey);
  }
}
