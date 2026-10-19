package monoid;

public final class CommandResetBundle extends Command {

  @Override
  protected void run() {
    requireAuth(AUTH_SAFE);

    reader.map();
    MonoidApplet.safe.resetBundle();

    writer.map((short) 1);
    {
      writer.text(Text.bundle);
      writer.bool(false);
    }
  }
}
