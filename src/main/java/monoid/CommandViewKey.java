package monoid;

import javacard.framework.JCSystem;
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
    boolean taproot = reader.key(Text.taproot) && (reader.is(CBOR.TYPE_MAP) || reader.bool());

    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_WEIERSTRASS:
      case Safe.TYPE_EDWARDS:
        if (taproot && !Safe.isTypeWeierstrass(type)) {
          MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
          return;
        }

        byte[] publicKey = Safe.isTypeWeierstrass(type)
          ? keystore.getWeierstrassKeyPublicKey(index, taproot ? readTaprootMerkleRoot() : null)
          : keystore.getEdwardsKeyPublicKey(index);

        writer.map((short) 1);
        {
          writer.text(Text.publicKey);
          writer.bytes(publicKey);
        }

        return;
    }

    byte[] curveName = reader.requireKey(Text.curve).text();

    WeierstrassCurve weierstrassCurve = WeierstrassCurve.getSharedCurve(curveName);
    EdwardsCurve edwardsCurve = weierstrassCurve == null
      ? EdwardsCurve.requireSharedCurve(curveName)
      : null;

    byte[] path = reader.requireKey(Text.path).bytes();
    byte[] seed = Safe.isTypeSeed(type) ? reader.requireKey(Text.seed).text() : null;

    if (taproot && weierstrassCurve == null) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      return;
    }

    byte[] merkleRoot = taproot ? readTaprootMerkleRoot() : null;

    short publicKeyLength = taproot
      ? CurveSECP256k1.KEY_LENGTH
      : weierstrassCurve != null
        ? weierstrassCurve.getPublicKeyLength()
        : edwardsCurve.getPublicKeyLength();

    byte[] data;

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_SEED:
        data = weierstrassCurve != null
          ? keystore.getSeedDerivedPublicKeyAndChainCode(
            index,
            seed,
            weierstrassCurve,
            path,
            merkleRoot
          )
          : keystore.getSeedDerivedPublicKeyAndChainCode(index, seed, edwardsCurve, path);
        break;
      case Safe.TYPE_MASTER:
        data = weierstrassCurve != null
          ? keystore.getMasterDerivedPublicKeyAndChainCode(
            index,
            weierstrassCurve,
            path,
            merkleRoot
          )
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

  private byte[] readTaprootMerkleRoot() {
    if (reader.requireKey(Text.taproot).is(CBOR.TYPE_MAP)) {
      reader.map();

      if (reader.key(Text.merkleRoot)) {
        return reader.bytes(CurveSECP256k1.KEY_LENGTH);
      }
    }

    return JCSystem.makeTransientByteArray((short) 0, JCSystem.CLEAR_ON_DESELECT);
  }
}
