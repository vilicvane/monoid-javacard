package monoid;

import javacard.framework.Util;
import javacard.security.MessageDigest;
import monoidlib.CBOR;
import monoidlib.CBORMap;
import monoidlib.Utils;

public class CommandSign extends Command {

  private final Object[] fields = {
    Text.index,
    Text.type,
    Text.derivation,
    Text.cipher,
    Text.taproot,
    Text.digest,
    Text.message,
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

    byte[] curve = null;
    byte[] path = null;
    byte[] context = null;

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

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_SEED: {
        CBORMap derivationRequest = request.requireKey(Text.derivation).map(derivationFields);

        byte[] derivation = derivationRequest.requireKey(Text.type).text();

        if (Utils.isEqual(BIP32Derivation.NAME, derivation)) {
          if (derivationRequest.key(Text.curve)) {
            MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
            return;
          }

          curve = WeierstrassCurve.SECP256k1;
        } else if (Utils.isEqual(SLIP10Ed25519Derivation.NAME, derivation)) {
          curve = derivationRequest.requireKey(Text.curve).text();

          if (!Utils.isEqual(EdwardsCurve.ED25519, curve)) {
            MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
            return;
          }
        } else if (Utils.isEqual(Monoid001Derivation.NAME, derivation)) {
          if (derivationRequest.key(Text.curve) || derivationRequest.key(Text.path)) {
            MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
            return;
          }

          curve = WeierstrassCurve.SECP256r1;
          context = derivationRequest.requireKey(Text.context).bytes();
        } else {
          MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
          return;
        }

        if (context == null) {
          path = derivationRequest.requireKey(Text.path).bytes();
        }

        break;
      }
      case Safe.TYPE_WEIERSTRASS:
      case Safe.TYPE_EDWARDS:
        if (request.key(Text.derivation)) {
          MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
          return;
        }

        break;
      default:
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
    }

    byte[] cipher = request.requireKey(Text.cipher).text();
    boolean hasTaproot = request.key(Text.taproot);
    byte[] signature;

    if (
      (hasTaproot && !Utils.isEqual(Signer.CIPHER_BIP340, cipher)) ||
      (context != null && !Utils.isEqual(Signer.CIPHER_ECDSA, cipher))
    ) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      return;
    }

    boolean taproot = hasTaproot && (reader.is(CBOR.TYPE_MAP) || reader.bool());

    if (Utils.isEqual(Signer.CIPHER_ECDSA, cipher)) {
      byte[] digest = request.requireKey(Text.digest).bytes();

      if (digest.length != MessageDigest.LENGTH_SHA_256) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
      }

      signature = keystore.signECDSADigest(index, curve, path, context, digest);
    } else if (Utils.isEqual(Signer.CIPHER_ED25519, cipher)) {
      short messageLength = request.requireKey(Text.message).bytesLength();

      signature = keystore.signED25519Message(
        index,
        curve,
        path,
        reader,
        reader.getOffset(),
        messageLength
      );
    } else if (Utils.isEqual(Signer.CIPHER_BIP340, cipher)) {
      byte[] digest = request.requireKey(Text.digest).bytes(CurveSECP256k1.KEY_LENGTH);
      byte[] merkleRoot = null;

      if (taproot) {
        if (request.requireKey(Text.taproot).is(CBOR.TYPE_MAP)) {
          reader.map();

          if (reader.key(Text.merkleRoot)) {
            merkleRoot = reader.bytes(CurveSECP256k1.KEY_LENGTH);
          }
        }

        if (merkleRoot == null) {
          merkleRoot = new byte[0];
        }
      }

      signature = keystore.signBIP340Digest(index, curve, path, digest, merkleRoot);
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
