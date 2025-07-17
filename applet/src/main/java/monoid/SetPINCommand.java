package monoid;

import javacard.framework.*;

import monoidsafe.MonoidSafe;
import monoidsafe.MonoidSafeApplet;

public final class SetPINCommand extends Command {
  public static void run() {
    byte auth = getAuth();

    MonoidSafe safe = MonoidApplet.safe;

    if (auth == AUTH_NONE) {
      if (safe.isPINSet() || MonoidApplet.pinSet) {
        // `MonoidApplet.pinSet` is redundant as MonoidApplet PIN is not allowed
        // to be set without safe PIN being set.

        sendError(ErrorCode.UNAUTHORIZED);
        return;
      }
    }

    ApduCBORReader reader = MonoidApplet.apduReader;

    reader.map();

    reader.requireKey(Text.safe);
    boolean safePIN = reader.bool();

    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(
        JCSystem.ARRAY_TYPE_BYTE,
        safePIN ? MonoidSafeApplet.MAX_PIN_SIZE : MonoidApplet.MAX_PIN_SIZE);

    reader.requireKey(Text.pin);
    short length = reader.text(buffer);

    if (safePIN) {
      if (safe.isPINSet()) {
        assertAuth(auth, AUTH_SAFE);
      }

      MonoidApplet.updateSafePIN(buffer, (short) 0, (byte) length);

      if (!MonoidApplet.pinSet) {
        MonoidApplet.updatePIN(buffer, (short) 0, (byte) length);
      }
    } else {
      if (!safe.isPINSet()) {
        // Set safe PIN is required before setting MonoidApplet PIN.
        sendError(ErrorCode.SAFE_PIN_NOT_SET);
        return;
      }

      if (MonoidApplet.pinSet) {
        assertAuth(auth, AUTH_ACCESS);
      }

      MonoidApplet.updatePIN(buffer, (short) 0, (byte) length);
    }

    writeEmptyMap();
  }
}
