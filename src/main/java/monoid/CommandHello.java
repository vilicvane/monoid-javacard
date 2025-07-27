package monoid;

public final class CommandHello extends Command {

  @Override
  protected void run() {
    reader.map();

    writer.map((short) 5);
    {
      writer.text(Text.id);
      writer.bytes(MonoidApplet.id);

      writer.text(Text.version);
      writer.integer(MonoidApplet.version);

      CommandSystemInformation.writeFeaturesKeyValue(writer);

      writer.text(Text.pin);
      if (MonoidApplet.pinSet) {
        writer.integer(MonoidApplet.pin.getTriesRemaining());
      } else {
        writer.bool(false);
      }

      writer.text(Text.safe);
      writer.map((short) 2);
      {
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
