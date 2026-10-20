package monoid;

public final class CommandReset extends Command {

  @Override
  protected void run() {
    reader.map();
    MonoidApplet.safe.reset();

    writer.map((short) 0);
  }
}
