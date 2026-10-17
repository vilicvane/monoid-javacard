package tests;

import javacard.framework.Shareable;
import monoidsafeidentity.SafeIdentityShareable;

/** Lets another test applet attempt to use a forwarded Identity interface. */
public interface IdentityCallerShareable extends Shareable {
  public SafeIdentityShareable getIdentity();
}
