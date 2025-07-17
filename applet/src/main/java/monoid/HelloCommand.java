package monoid;

import javacard.framework.*;

import monoidsafe.MonoidSafe;

public final class HelloCommand extends Command {
  public static void run() {
    ApduCBORWriter writer = MonoidApplet.apduWriter;

    OwnerPIN pin = MonoidApplet.pin;
    MonoidSafe safe = MonoidApplet.safe;

    writer.map((short) 3);
    {
      writer.text(Text.versions);
      writer.map((short) 2);
      {
        writer.text(Text.monoid);
        writer.integer(MonoidApplet.version);

        writer.text(Text.javacard);
        writer.array((short) 2);
        {
          writer.integer((short) (JCSystem.getVersion() >> 8));
          writer.integer((short) (JCSystem.getVersion() & 0xFF));
        }
      }

      writer.text(Text.pin);
      if (MonoidApplet.pinSet) {
        writer.integer(pin.getTriesRemaining());
      } else {
        writer.bool(false);
      }

      writer.text(Text.safe);
      writer.map((short) 2);
      {
        writer.text(Text.pin);
        if (safe.isPINSet()) {
          writer.integer(safe.getPINTriesRemaining());
        } else {
          writer.bool(false);
        }

        writer.text(Text.unlocked);
        writer.bool(MonoidApplet.isSafeUnlocked());
      }
    }

    writer.send();
  }
}
