package monoid;

import monoidsafe.MonoidSafe;

public class CommandSign extends Command {
  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    Keystore keystore = MonoidApplet.keystore;

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(MonoidSafe.INDEX_LENGTH);
    Curve curve = Curve.requireSharedCurve(reader.requireKey(Text.curve).text());

    byte[] cipher = reader.requireKey(Text.cipher).text();
    byte[] digest = reader.requireKey(Text.digest).bytes();

    byte type = index[0];

    byte[] signature;

    if (type == Safe.TYPE_KEY) {
      signature = keystore.sign(index, curve, cipher, null, null, digest);
    } else {
      byte[] path = reader.requireKey(Text.path).bytes();

      byte[] seed;

      switch (type) {
        case Safe.TYPE_SEED:
          seed = reader.requireKey(Text.seed).text();
          break;
        case Safe.TYPE_MASTER:
          seed = null;
          break;
        default:
          MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
          return;
      }

      signature = keystore.sign(index, curve, cipher, seed, path, digest);
    }

    writer.map((short) 1);
    {
      writer.text(Text.signature);
      writer.bytes(signature);
    }
  }
}
