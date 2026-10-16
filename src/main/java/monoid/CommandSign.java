package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import monoidsafe.SafeShareable;

public class CommandSign extends Command {

  @Override
  protected void run() {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    Keystore keystore = MonoidApplet.keystore;

    reader.map();
    reader.snapshot();

    byte[] index = reader.requireKey(Text.index).bytes(SafeShareable.INDEX_LENGTH);

    byte[] curve = null;
    byte[] path = null;

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

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_SEED:
      case Safe.TYPE_MASTER: {
        reader.requireKey(Text.derivation).map();

        byte[] derivation = reader.requireKey(Text.type).text();

        if (Utils.isEqual(LibBIP32.NAME, derivation)) {
          if (reader.key(Text.curve)) {
            MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
            return;
          }

          curve = WeierstrassCurve.SECP256k1;
        } else if (Utils.isEqual(LibSLIP10Ed25519.NAME, derivation)) {
          curve = reader.requireKey(Text.curve).text();

          if (!Utils.isEqual(EdwardsCurve.ED25519, curve)) {
            MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
            return;
          }
        } else {
          MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
          return;
        }

        path = reader.requireKey(Text.path).bytes();

        reader.restore();
        break;
      }
      case Safe.TYPE_WEIERSTRASS:
      case Safe.TYPE_EDWARDS:
        if (reader.key(Text.derivation)) {
          MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
          return;
        }

        break;
      default:
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
    }

    byte[] cipher = reader.requireKey(Text.cipher).text();
    boolean hasTaproot = reader.key(Text.taproot);
    byte[] signature;

    if (hasTaproot && !Utils.isEqual(Signer.CIPHER_BIP340, cipher)) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
      return;
    }

    boolean taproot = hasTaproot && (reader.is(CBOR.TYPE_MAP) || reader.bool());

    if (Utils.isEqual(Signer.CIPHER_ECDSA, cipher)) {
      byte[] digest = reader.requireKey(Text.digest).bytes();

      if (digest.length != MessageDigest.LENGTH_SHA_256) {
        MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
        return;
      }

      signature = keystore.signECDSADigest(index, curve, path, digest);
    } else if (Utils.isEqual(Signer.CIPHER_ED25519, cipher)) {
      short messageLength = reader.requireKey(Text.message).bytesLength();

      signature = keystore.signED25519Message(
        index,
        curve,
        path,
        reader,
        reader.getOffset(),
        messageLength
      );
    } else if (Utils.isEqual(Signer.CIPHER_BIP340, cipher)) {
      byte[] digest = reader.requireKey(Text.digest).bytes(CurveSECP256k1.KEY_LENGTH);
      byte[] merkleRoot = null;

      if (taproot) {
        if (reader.requireKey(Text.taproot).is(CBOR.TYPE_MAP)) {
          reader.map();

          if (reader.key(Text.merkleRoot)) {
            merkleRoot = reader.bytes(CurveSECP256k1.KEY_LENGTH);
          }
        }

        if (merkleRoot == null) {
          merkleRoot = JCSystem.makeTransientByteArray((short) 0, JCSystem.CLEAR_ON_DESELECT);
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
