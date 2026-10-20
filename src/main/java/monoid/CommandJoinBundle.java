package monoid;

public final class CommandJoinBundle extends Command {

  @Override
  protected void run() {
    requireAuth(AUTH_SAFE);

    reader.map();
    byte[] senderPublicKey = reader.requireKey(Text.senderPublicKey).bytesGlobal((short) 65);
    byte[] data = reader.requireKey(Text.data).bytesGlobal();
    byte[] bundle = MonoidApplet.safe.joinBundle(senderPublicKey, data);

    writer.map((short) 1);
    {
      writer.text(Text.bundle);
      writer.bytes(bundle);
    }
  }
}
