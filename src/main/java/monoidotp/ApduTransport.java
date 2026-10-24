package monoidotp;

import monoidlib.CBORApduReader;
import monoidlib.CBORApduWriter;

final class ApduTransport extends monoidlib.ApduTransport {

  ApduTransport(CBORApduReader reader, CBORApduWriter writer) {
    super(reader, writer);
  }

  @Override
  protected boolean supports(byte instruction) {
    return Command.get(instruction) != null;
  }

  @Override
  protected void execute(byte instruction) {
    Command.get(instruction).executeCommand();
  }
}
