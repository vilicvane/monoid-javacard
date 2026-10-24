package monoidotp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import monoid.Monoid;

final class CommandCalculate extends Command {

  @Override
  protected void run() {
    OTPBatch batch = MonoidOTPApplet.takeBatch();
    reader.map();

    if (batch == null || !batch.isPrepared()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    Monoid monoid = MonoidOTPApplet.connect();
    monoid.consumeUserAuthentication();
    batch.calculate(monoid, writer);
  }
}
