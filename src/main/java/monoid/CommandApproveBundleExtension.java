package monoid;

import monoidlib.CBORWriter;

public final class CommandApproveBundleExtension extends Command {

  private final SafeDataResponse response = new SafeDataResponse();

  @Override
  protected void run() {
    requireAuth(AUTH_SECRET);

    reader.map();

    byte[] request = reader.requireKey(Text.data).bytesGlobal();

    SafeDataSource data = MonoidApplet.safe.approveBundleExtension(request);
    byte[] publicKey = MonoidApplet.safe.getPublicKey();

    short prefixLength = (short) (3 +
      Text.publicKey.length +
      CBORWriter.metadataLength((short) publicKey.length) +
      publicKey.length +
      Text.data.length);
    short length = response.start(writer, data, prefixLength);

    writer.map((short) 2);
    {
      writer.text(Text.publicKey);
      writer.bytes(publicKey);

      writer.text(Text.data);
      writer.bytesLength(length);
      response.writeData(writer);
    }
  }
}
