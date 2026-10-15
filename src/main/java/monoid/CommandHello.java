package monoid;

import static monoidsafe.Constants.SAFE_FALSE;
import static monoidsafe.Constants.SAFE_TRUE;

public final class CommandHello extends Command {

  @Override
  protected void run() {
    reader.map();

    writer.map((short) 5);
    {
      writer.text(Text.version);
      writer.integer(MonoidApplet.version);

      writer.text(Text.id);
      writer.bytes(MonoidApplet.id);

      CommandSystemInformation.writeFeaturesKeyValue(writer);

      writer.text(Text.pin);
      if (MonoidApplet.getPINSetResult(SAFE_FALSE) == SAFE_TRUE) {
        writer.integer(MonoidApplet.pin.getTriesRemaining());
      } else {
        writer.bool(false);
      }

      writer.text(Text.safe);
      writer.map((short) 3);
      {
        writer.text(Text.id);
        writer.bytes(MonoidApplet.safe.getId());

        writer.text(Text.pin);
        if (MonoidApplet.safe.isPINSet()) {
          writer.integer(MonoidApplet.safe.getPINTriesRemaining());
        } else {
          writer.bool(false);
        }

        writer.text(Text.unlocked);
        writer.bool(MonoidApplet.isSafeUnlocked());
      }
    }
  }
}
