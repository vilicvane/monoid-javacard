package monoidsecuritykey;

import javacard.framework.JCSystem;
import monoid.Monoid;
import monoidlib.CBORReader;
import monoidlib.CBORWriter;

final class CommandReset extends Command {

  @Override
  void execute(CBORReader reader, CBORWriter writer) {
    assertEmpty(reader);
    Monoid monoid = MonoidSecurityKeyApplet.connect();
    // Remove credentials before clearing their PIN. If the PIN reset fails, repeating
    // Reset completes it without leaving old credentials protected by a new PIN.
    monoid.removeAll(Constants.CREDENTIAL_TYPE);
    authenticator.credentials.clear();
    authenticator.pin.reset();
    JCSystem.requestObjectDeletion();
  }
}
