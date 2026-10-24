package monoidotp;

final class CommandHello extends Command {

  @Override
  protected void run() {
    reader.map();

    writer.map((short) 2);
    writer.text(Text.version);
    writer.bytes(Constants.VERSION);
    writer.text(Text.batchSize);
    writer.integer(Constants.BATCH_SIZE);
  }
}
