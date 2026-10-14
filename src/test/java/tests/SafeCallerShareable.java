package tests;

import javacard.framework.Shareable;
import monoidsafe.SafeItemShareable;
import monoidsafe.SafeShareable;

/** Lets cooperating test applets forward their cached Safe interfaces. */
public interface SafeCallerShareable extends Shareable {
  public SafeShareable getSafe();

  public SafeItemShareable getItem();
}
