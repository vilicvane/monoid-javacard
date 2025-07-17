package monoid;

import javacard.framework.*;

import monoidsafe.MonoidSafe;

public final class HelloCommand {
  public static void run(
      CBORWriter writer,
      short version,
      OwnerPIN pin,
      MonoidSafe safe, boolean safeUnlocked) {
    writer.map((short) 3);

    {
      writer.text(Text.versions);
      writer.map((short) 2);

      writer.text(Text.monoid);
      writer.integer(version);

      writer.text(Text.javacard);
      writer.array((short) 2);
      writer.integer((short) (JCSystem.getVersion() >> 8));
      writer.integer((short) (JCSystem.getVersion() & 0xFF));
    }

    {
      writer.text(Text.pin);

      if (pin != null) {
        writer.integer(pin.getTriesRemaining());
      } else {
        writer.bool(false);
      }
    }

    {
      writer.text(Text.safe);
      writer.map((short) 2);

      writer.text(Text.pin);

      if (safe.isPINSet()) {
        writer.integer(safe.getPINTriesRemaining());
      } else {
        writer.bool(false);
      }

      writer.text(Text.unlocked);
      writer.bool(safeUnlocked);
    }
  }
}
