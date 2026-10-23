package monoid;

public final class CommandExtendBundle extends Command {

  private final SafeDataResponse response = new SafeDataResponse();

  @Override
  protected void run() {
    requireAuth(AUTH_SECRET);

    reader.map();

    byte[] publicKey = reader.requireKey(Text.publicKey).bytesGlobal((short) 65);

    SafeDataSource data = MonoidApplet.safe.extendBundle(publicKey);

    short length = response.start(writer, data, (short) (2 + Text.data.length));

    writer.map((short) 1);
    {
      writer.text(Text.data);
      writer.bytesLength(length);
      response.writeData(writer);
    }
  }
}
