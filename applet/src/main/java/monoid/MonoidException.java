package monoid;

import javacard.framework.*;

public class MonoidException extends CardException {
  protected short reason;
  protected byte[] code;

  public MonoidException() {
    super((short) 0);
  }

  public void send() {
    Command.sendError(code);
  }
}
