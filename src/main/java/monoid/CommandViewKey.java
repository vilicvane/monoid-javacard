package monoid;

import javacard.framework.Util;
import monoidsafe.MonoidSafe;

public final class CommandViewKey extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    Keystore keystore = MonoidApplet.keystore;

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(MonoidSafe.INDEX_LENGTH);

    short type = Util.getShort(index, MonoidSafe.INDEX_OFFSET);

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_EC:
        writer.map((short) 1);
        {
          writer.text(Text.publicKey);
          writer.bytes(keystore.getECKeyPublicKey(index));
        }

        return;
    }

    Curve curve = Curve.requireSharedCurve(reader.requireKey(Text.curve).text());

    byte[] path = reader.requireKey(Text.path).bytes();

    short publicKeyLength = curve.getPublicKeyLength();

    byte[] data;

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_SEED:
        byte[] seed = reader.requireKey(Text.seed).text();
        data = keystore.getSeedDerivedPublicKeyAndChainCode(index, seed, curve, path);
        break;
      case Safe.TYPE_MASTER:
        data = keystore.getMasterDerivedPublicKeyAndChainCode(index, curve, path);
        break;
      default:
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
    }

    writer.map((short) 2);
    {
      writer.text(Text.publicKey);
      writer.bytes(data, (short) 0, publicKeyLength);

      writer.text(Text.chainCode);
      writer.bytes(data, publicKeyLength, (short) (data.length - publicKeyLength));
    }
  }
}
