package monoid;

import javacard.framework.Util;
import monoidsafe.SafeShareable;

public final class CommandViewKey extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    Keystore keystore = MonoidApplet.keystore;

    reader.map();

    byte[] index = reader.requireKey(Text.index).bytes(SafeShareable.INDEX_LENGTH);

    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_EC:
        writer.map((short) 1);
        {
          writer.text(Text.publicKey);
          writer.bytes(keystore.getECKeyPublicKey(index));
        }

        return;
    }

    byte[] curveName = reader.requireKey(Text.curve).text();

    WeierstrassCurve weierstrassCurve = WeierstrassCurve.getSharedCurve(curveName);
    EdwardsCurve edwardsCurve = weierstrassCurve == null
      ? EdwardsCurve.requireSharedCurve(curveName)
      : null;

    byte[] path = reader.requireKey(Text.path).bytes();

    short publicKeyLength = weierstrassCurve != null
      ? weierstrassCurve.getPublicKeyLength()
      : edwardsCurve.getPublicKeyLength();

    byte[] data;

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_SEED:
        byte[] seed = reader.requireKey(Text.seed).text();
        data = weierstrassCurve != null
          ? keystore.getSeedDerivedPublicKeyAndChainCode(index, seed, weierstrassCurve, path)
          : keystore.getSeedDerivedPublicKeyAndChainCode(index, seed, edwardsCurve, path);
        break;
      case Safe.TYPE_MASTER:
        data = weierstrassCurve != null
          ? keystore.getMasterDerivedPublicKeyAndChainCode(index, weierstrassCurve, path)
          : keystore.getMasterDerivedPublicKeyAndChainCode(index, edwardsCurve, path);
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
