package monoid;

import javacard.framework.Util;
import monoidsafe.SafeShareable;

public class CommandSign extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    Keystore keystore = MonoidApplet.keystore;

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(SafeShareable.INDEX_LENGTH);

    byte[] cipher = reader.requireKey(Text.cipher).text();
    byte[] digest = reader.requireKey(Text.digest).bytes();

    byte[] signature;

    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_SEED: {
        byte[] seed = reader.requireKey(Text.seed).text();
        byte[] curve = reader.requireKey(Text.curve).text();
        byte[] path = reader.requireKey(Text.path).bytes();

        signature = keystore.sign(index, seed, curve, path, cipher, digest);
        break;
      }
      case Safe.TYPE_MASTER: {
        byte[] curve = reader.requireKey(Text.curve).text();
        byte[] path = reader.requireKey(Text.path).bytes();

        signature = keystore.sign(index, null, curve, path, cipher, digest);
        break;
      }
      case Safe.TYPE_EC:
        signature = keystore.sign(index, null, null, null, cipher, digest);
        break;
      default:
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
    }

    writer.map((short) 1);
    {
      writer.text(Text.signature);
      writer.bytes(signature);
    }
  }
}
