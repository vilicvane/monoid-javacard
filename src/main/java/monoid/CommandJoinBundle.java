package monoid;

public final class CommandJoinBundle extends Command {

  @Override
  protected void run() {
    requireAuth(AUTH_SECRET);

    reader.map();

    byte[] publicKey = reader.requireKey(Text.publicKey).bytesGlobal((short) 65);
    byte[] data = reader.requireKey(Text.data).bytesGlobal();

    byte[] bundle = MonoidApplet.safe.joinBundle(publicKey, data);

    writer.map((short) 1);
    {
      writer.text(Text.bundle);
      writer.bytes(bundle);
    }
  }
}
