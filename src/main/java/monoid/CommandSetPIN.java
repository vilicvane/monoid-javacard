package monoid;

public final class CommandSetPIN extends Command {

  @Override
  protected void run() throws MonoidException {
    MonoidApplet.checkPINUpdate();

    reader.map();

    byte[] pin = reader.requireKey(Text.pin).text();

    boolean secretPIN = reader.key(Text.secret) && reader.boolTrue();

    if (secretPIN) {
      MonoidApplet.updateSecretPIN(pin);
    } else {
      MonoidApplet.updatePIN(pin);
    }

    writeEmptyMap();
  }
}
