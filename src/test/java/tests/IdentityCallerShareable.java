package tests;

import javacard.framework.Shareable;
import monoididentity.CommunicationDataShareable;
import monoididentity.IdentityShareable;

/** Lets another test applet attempt to use a forwarded Identity interface. */
public interface IdentityCallerShareable extends Shareable {
  public IdentityShareable getIdentity();

  public CommunicationDataShareable getResult();
}
