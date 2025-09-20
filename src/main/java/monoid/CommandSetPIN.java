package monoid;

public final class CommandSetPIN extends Command {

  @Override
  protected void run() throws MonoidException {
    byte auth = getAuth();

    Safe safe = MonoidApplet.safe;

    if (auth == 0) {
      if (safe.isPINSet() || MonoidApplet.pinSet) {
        // `MonoidApplet.pinSet` is redundant as MonoidApplet PIN is not allowed
        // to be set without safe PIN being set.

        MonoidException.throwIt(MonoidException.CODE_UNAUTHORIZED);
      }
    }

    reader.map();

    byte[] pin = Utils.duplicateAsGlobal(reader.requireKey(Text.pin).text());

    boolean safePIN = reader.key(Text.safe) && reader.boolTrue();

    if (safePIN) {
      if (safe.isPINSet()) {
        assertAuth(auth, AUTH_SAFE);
      }

      MonoidApplet.updateSafePIN(pin);

      if (!MonoidApplet.pinSet) {
        MonoidApplet.updatePIN(pin);
      }
    } else {
      if (!safe.isPINSet()) {
        // Set safe PIN is required before setting MonoidApplet PIN.
        MonoidException.throwIt(MonoidException.CODE_SAFE_PIN_NOT_SET);
      }

      if (MonoidApplet.pinSet) {
        assertAuth(auth, AUTH_SAFE);
      }

      MonoidApplet.updatePIN(pin);
    }

    sendEmptyMap();
  }
}
