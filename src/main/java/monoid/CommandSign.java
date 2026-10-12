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

    byte[] seed = null;
    byte[] curve = null;
    byte[] path = null;

    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_SEED:
        seed = reader.requireKey(Text.seed).text();
        curve = reader.requireKey(Text.curve).text();
        path = reader.requireKey(Text.path).bytes();
        break;
      case Safe.TYPE_MASTER:
        curve = reader.requireKey(Text.curve).text();
        path = reader.requireKey(Text.path).bytes();
        break;
      case Safe.TYPE_WEIERSTRASS:
      case Safe.TYPE_EDWARDS:
        break;
      default:
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
    }

    byte[] cipher = reader.requireKey(Text.cipher).text();
    byte[] signature;

    if (Utils.isEqual(Signer.CIPHER_ECDSA, cipher)) {
      byte[] digest = reader.requireKey(Text.digest).bytes();

      signature = keystore.signECDSADigest(index, seed, curve, path, digest);
    } else if (Utils.isEqual(Signer.CIPHER_EDDSA, cipher)) {
      short messageLength = reader.requireKey(Text.message).bytesLength();

      signature = keystore.signEDDSAMessage(
        index,
        seed,
        curve,
        path,
        reader,
        reader.getOffset(),
        messageLength
      );
    } else {
      SignerException.throwIt(SignerException.REASON_UNSUPPORTED_CIPHER);
      return;
    }

    writer.map((short) 1);
    {
      writer.text(Text.signature);
      writer.bytes(signature);
    }
  }
}
