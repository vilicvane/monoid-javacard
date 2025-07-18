package monoid;

import javacard.framework.*;

import monoidsafe.MonoidSafe;

public final class CommandHello extends Command {
  @Override
  protected void run() {
    OwnerPIN pin = MonoidApplet.pin;
    MonoidSafe safe = MonoidApplet.safe;

    writer.map((short) 4);
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

      writer.text(Text.features);
      writer.map((short) 2);
      {
        writer.text(Text.curves);
        Curve.writeSupportedCurves(writer);

        writer.text(Text.ciphers);
        Signer.writeSupportedCiphers(writer);
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
