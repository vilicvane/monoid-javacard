package monoid;

public class CommandAuthenticate extends Command {

  @Override
  protected void run() throws MonoidException {
    authenticate();

    sendEmptyMap();
  }
}
