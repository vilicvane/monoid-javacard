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
    reader.snapshot();

    byte[] index = reader.requireKey(Text.index).bytes(SafeShareable.INDEX_LENGTH);

    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);
    short declaredType = Safe.type(reader.requireKey(Text.type));

    if (
      declaredType !=
        (Safe.isTypeSeed(type) || Safe.isTypeMaster(type)
            ? (short) (type & Safe.TYPE_CATEGORY_MASK)
            : type) ||
      reader.key(Text.seed) ||
      reader.key(Text.curve) ||
      reader.key(Text.path)
    ) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      return;
    }

    boolean hasTaproot = reader.key(Text.taproot);
    boolean taproot = hasTaproot && (reader.is(CBOR.TYPE_MAP) || reader.bool());

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_WEIERSTRASS:
      case Safe.TYPE_EDWARDS:
        if (
          (hasTaproot && type != Safe.TYPE_WEIERSTRASS_SECP256K1) || reader.key(Text.derivation)
        ) {
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
      case Safe.TYPE_SEED:
      case Safe.TYPE_MASTER:
        break;
      default:
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
    }

    reader.requireKey(Text.derivation).map();

    byte[] derivation = reader.requireKey(Text.type).text();
    byte[] curveName;

    if (Utils.isEqual(LibBIP32.NAME, derivation)) {
      if (reader.key(Text.curve)) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
      }

      curveName = WeierstrassCurve.SECP256k1;
    } else if (Utils.isEqual(LibSLIP10Ed25519.NAME, derivation)) {
      curveName = reader.requireKey(Text.curve).text();

      if (!Utils.isEqual(EdwardsCurve.ED25519, curveName)) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
      }
    } else if (Utils.isEqual(LibMonoid001.NAME, derivation)) {
      if (hasTaproot || reader.key(Text.curve) || reader.key(Text.path)) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
      }

      byte[] context = reader.requireKey(Text.context).bytes();

      reader.restore();

      byte[] publicKey = Safe.isTypeSeed(type)
        ? keystore.getMonoid001PublicKeyFromSeed(index, context)
        : keystore.getMonoid001PublicKeyFromMaster(index, context);

      writer.map((short) 1);
      {
        writer.text(Text.publicKey);
        writer.bytes(publicKey);
      }

      return;
    } else {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      return;
    }

    byte[] path = reader.requireKey(Text.path).bytes();

    reader.restore();

    WeierstrassCurve weierstrassCurve = WeierstrassCurve.getSharedCurve(curveName);
    EdwardsCurve edwardsCurve = weierstrassCurve == null
      ? EdwardsCurve.requireSharedCurve(curveName)
      : null;

    if (hasTaproot && weierstrassCurve == null) {
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
          ? keystore.getBIP32PublicKeyAndChainCodeFromSeed(
            index,
            weierstrassCurve,
            path,
            merkleRoot
          )
          : keystore.getSLIP10Ed25519PublicKeyAndChainCodeFromSeed(index, edwardsCurve, path);
        break;
      case Safe.TYPE_MASTER:
        data = weierstrassCurve != null
          ? keystore.getBIP32PublicKeyAndChainCodeFromMaster(
            index,
            weierstrassCurve,
            path,
            merkleRoot
          )
          : keystore.getSLIP10Ed25519PublicKeyAndChainCodeFromMaster(index, edwardsCurve, path);
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
