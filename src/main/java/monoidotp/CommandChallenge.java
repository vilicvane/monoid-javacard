package monoidotp;

import javacard.security.RandomData;

final class CommandChallenge extends Command {

  @Override
  protected void run() {
    MonoidOTPApplet.takeBatch();
    reader.map();
    MonoidOTPApplet.connect().revokeUserAuthentication();

    byte[] challenge = new byte[Constants.CHALLENGE_LENGTH];
    RandomData.getInstance(RandomData.ALG_TRNG).nextBytes(
      challenge,
      (short) 0,
      (short) challenge.length
    );
    MonoidOTPApplet.setBatch(new OTPBatch(challenge));

    writer.map((short) 1);
    writer.text(Text.challenge);
    writer.bytes(challenge);
  }
}
