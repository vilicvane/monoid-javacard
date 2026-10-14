package monoid;

public final class CommandSetPIN extends Command {

  @Override
  protected void run() throws MonoidException {
    MonoidApplet.checkPINUpdate();

    reader.map();

    byte[] pin = Utils.duplicateAsGlobal(reader.requireKey(Text.pin).text());

    boolean safePIN = reader.key(Text.safe) && reader.boolTrue();

    if (safePIN) {
      MonoidApplet.updateSafePIN(pin);
    } else {
      MonoidApplet.updatePIN(pin);
    }

    sendEmptyMap();
  }
}
