package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public final class CommandViewKey extends Command {

  private final Object[] fields = {
    Text.index,
    Text.type,
    Text.derivation,
    Text.taproot,
    Text.seed,
    Text.curve,
    Text.path,
  };

  private final Object[] derivationFields = { Text.type, Text.curve, Text.path, Text.context };

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.safe.checkAccess();

    Keystore keystore = MonoidApplet.keystore;

    CBORMap request = reader.map(fields);

    byte[] index = request.requireKey(Text.index).bytes(Safe.INDEX_LENGTH);

    short type = Util.getShort(index, Safe.INDEX_TYPE_OFFSET);
    short declaredType = Safe.type(request.requireKey(Text.type));

    if (
      declaredType != (Safe.isTypeSeed(type) ? (short) (type & Safe.TYPE_CATEGORY_MASK) : type) ||
      request.key(Text.seed) ||
      request.key(Text.curve) ||
      request.key(Text.path)
    ) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      return;
    }

    boolean hasTaproot = request.key(Text.taproot);
    boolean taproot = hasTaproot && (reader.is(CBOR.TYPE_MAP) || reader.bool());

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_WEIERSTRASS:
      case Safe.TYPE_EDWARDS:
        if (
          (hasTaproot && type != Safe.TYPE_WEIERSTRASS_SECP256K1) || request.key(Text.derivation)
        ) {
          MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
          return;
        }

        byte[] publicKey = Safe.isTypeWeierstrass(type)
          ? keystore.getWeierstrassKeyPublicKey(
            index,
            taproot ? readTaprootMerkleRoot(request) : null
          )
          : keystore.getEdwardsKeyPublicKey(index);

        writer.map((short) 1);
        {
          writer.text(Text.publicKey);
          writer.bytes(publicKey);
        }

        return;
      case Safe.TYPE_SEED:
        break;
      default:
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
    }

    CBORMap derivationRequest = request.requireKey(Text.derivation).map(derivationFields);

    byte[] derivation = derivationRequest.requireKey(Text.type).text();
    byte[] curveName;

    if (Utils.isEqual(BIP32Derivation.NAME, derivation)) {
      if (derivationRequest.key(Text.curve)) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
      }

      curveName = WeierstrassCurve.SECP256k1;
    } else if (Utils.isEqual(SLIP10Ed25519Derivation.NAME, derivation)) {
      curveName = derivationRequest.requireKey(Text.curve).text();

      if (!Utils.isEqual(EdwardsCurve.ED25519, curveName)) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
      }
    } else if (Utils.isEqual(Monoid001Derivation.NAME, derivation)) {
      if (hasTaproot || derivationRequest.key(Text.curve) || derivationRequest.key(Text.path)) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
      }

      byte[] context = derivationRequest.requireKey(Text.context).bytes();

      byte[] publicKey = keystore.getMonoid001PublicKeyFromSeed(index, context);

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

    byte[] path = derivationRequest.requireKey(Text.path).bytes();

    WeierstrassCurve weierstrassCurve = WeierstrassCurve.getSharedCurve(curveName);
    EdwardsCurve edwardsCurve = weierstrassCurve == null
      ? EdwardsCurve.requireSharedCurve(curveName)
      : null;

    if (hasTaproot && weierstrassCurve == null) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      return;
    }

    byte[] merkleRoot = taproot ? readTaprootMerkleRoot(request) : null;

    short publicKeyLength = taproot
      ? CurveSECP256k1.KEY_LENGTH
      : weierstrassCurve != null
        ? weierstrassCurve.getPublicKeyLength()
        : edwardsCurve.getPublicKeyLength();

    byte[] data = weierstrassCurve != null
      ? keystore.getBIP32PublicKeyAndChainCodeFromSeed(index, weierstrassCurve, path, merkleRoot)
      : keystore.getSLIP10Ed25519PublicKeyAndChainCodeFromSeed(index, edwardsCurve, path);

    writer.map((short) 2);
    {
      writer.text(Text.publicKey);
      writer.bytes(data, (short) 0, publicKeyLength);

      writer.text(Text.chainCode);
      writer.bytes(data, publicKeyLength, (short) (data.length - publicKeyLength));
    }
  }

  private byte[] readTaprootMerkleRoot(CBORMap request) {
    if (request.requireKey(Text.taproot).is(CBOR.TYPE_MAP)) {
      reader.map();

      if (reader.key(Text.merkleRoot)) {
        return reader.bytes(CurveSECP256k1.KEY_LENGTH);
      }
    }

    return JCSystem.makeTransientByteArray((short) 0, JCSystem.CLEAR_ON_DESELECT);
  }
}
