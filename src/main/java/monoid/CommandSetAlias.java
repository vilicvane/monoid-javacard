package monoid;

public final class CommandSetAlias extends Command {

  @Override
  protected void run() {
    requireAuth(AUTH_SECRET);

    reader.map();

    MonoidApplet.safe.setAlias(reader.requireKey(Text.alias).text());

    sendEmptyMap();
  }
}
