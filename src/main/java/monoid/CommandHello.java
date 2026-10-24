package monoid;

import static monoid.Constants.SAFE_FALSE;
import static monoid.Constants.SAFE_TRUE;

public final class CommandHello extends Command {

  @Override
  protected void run() {
    reader.map();

    writer.map((short) 6);
    {
      writer.text(Text.version);
      writer.integer(Constants.MONOID_VERSION);

      writer.text(Text.id);
      writer.bytes(MonoidApplet.safe.getId());

      writer.text(Text.publicKey);
      writer.bytes(MonoidApplet.safe.getPublicKey());

      writer.text(Text.authority);
      byte[] authority = MonoidApplet.safe.getAuthority();
      if (authority != null) {
        writer.text(authority);
      } else {
        writer.bool(false);
      }

      writer.text(Text.bundle);
      byte[] bundle = MonoidApplet.safe.getBundle();
      if (bundle != null) {
        writer.bytes(bundle);
      } else {
        writer.bool(false);
      }

      writer.text(Text.pins);
      writer.map((short) 2);
      {
        writer.text(Text.access);
        if (MonoidApplet.getPINSetResult(SAFE_FALSE) == SAFE_TRUE) {
          writer.integer(MonoidApplet.pin.getTriesRemaining());
        } else {
          writer.bool(false);
        }

        writer.text(Text.secret);
        if (MonoidApplet.safe.getPINSetResult(SAFE_FALSE) == SAFE_TRUE) {
          writer.integer(MonoidApplet.safe.getPINTriesRemaining());
        } else {
          writer.bool(false);
        }
      }
    }
  }
}
