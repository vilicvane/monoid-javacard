package monoid;

import javacard.framework.OwnerPIN;

import monoidsafe.MonoidSafe;

public final class CommandHello extends Command {
  @Override
  protected void run() {
    OwnerPIN pin = MonoidApplet.pin;
    MonoidSafe safe = MonoidApplet.safe;

    reader.map();

    writer.map((short) 4);
    {
      writer.text(Text.version);
      writer.integer(MonoidApplet.version);

      CommandSystemInformation.writeFeaturesKeyValue(writer);

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
  }
}
