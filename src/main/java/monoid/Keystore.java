package monoid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.Key;
import monoidsafe.SafeShareable;

public final class Keystore {

  public static final byte SEED_512_LENGTH = 64;

  public static final byte MASTER_LENGTH = LibBIP32.COMPONENT_LENGTH * 2;
  public static final byte MASTER_PRIVATE_KEY_OFFSET = SafeShareable.INDEX_LENGTH;
  public static final byte MASTER_CHAIN_CODE_OFFSET =
    MASTER_PRIVATE_KEY_OFFSET + LibBIP32.COMPONENT_LENGTH;

  private Safe safe;

  public Keystore(Safe safe) {
    this.safe = safe;
  }

  public byte[] getSeedDerivedPublicKeyAndChainCode(
    byte[] index,
    byte[] seed,
    WeierstrassCurve curve,
    byte[] path
  ) {
    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    if (!Safe.isTypeSeed(type)) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    byte[] key = requireKey(index);

    byte[] master = deriveMasterFromSeed(key, seed);

    return derivePublicKeyAndChainCodeFromMaster(curve, master, path);
  }

  public byte[] getMasterDerivedPublicKeyAndChainCode(
    byte[] index,
    WeierstrassCurve curve,
    byte[] path
  ) {
    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    if (!Safe.isTypeMaster(type)) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    byte[] key = requireKey(index);

    return derivePublicKeyAndChainCodeFromMaster(curve, key, path);
  }

  public byte[] getSeedDerivedPublicKeyAndChainCode(
    byte[] index,
    byte[] seed,
    EdwardsCurve curve,
    byte[] path
  ) {
    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    if (!Safe.isTypeSeed(type)) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    byte[] key = requireKey(index);

    byte[] master = deriveMasterFromSeed(key, seed);

    return derivePublicKeyAndChainCodeFromMaster(curve, master, path);
  }

  public byte[] getMasterDerivedPublicKeyAndChainCode(
    byte[] index,
    EdwardsCurve curve,
    byte[] path
  ) {
    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    if (!Safe.isTypeMaster(type)) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    byte[] key = requireKey(index);

    return derivePublicKeyAndChainCodeFromMaster(curve, key, path);
  }

  public byte[] getWeierstrassKeyPublicKey(byte[] index) {
    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    WeierstrassCurve curve;

    switch (type) {
      case Safe.TYPE_WEIERSTRASS_SECP256K1:
        curve = WeierstrassCurve.secp256k1;
        break;
      default:
        KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
        return null;
    }

    byte[] key = requireKey(index);

    ECPrivateKey privateKey = curve.getSharedPrivateKey(key, (short) 0);

    return curve.derivePublicKey(privateKey);
  }

  public byte[] getEdwardsKeyPublicKey(byte[] index) {
    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    EdwardsCurve curve;

    switch (type) {
      case Safe.TYPE_EDWARDS_ED25519:
        curve = EdwardsCurve.ed25519;
        break;
      default:
        KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
        return null;
    }

    byte[] key = requireKey(index);

    if (key.length != curve.getKeyLength()) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    ED25519Key privateKey = curve.getSharedPrivateKey(key, (short) 0);

    try {
      return curve.derivePublicKey(privateKey);
    } finally {
      privateKey.clear();
    }
  }

  public byte[] signECDSADigest(
    byte[] index,
    byte[] seed,
    byte[] curveName,
    byte[] path,
    byte[] digest
  ) throws KeystoreException, CurveException, SignerException {
    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    byte[] key = requireKey(index);

    if (Safe.isTypeSeed(type)) {
      byte[] master = deriveMasterFromSeed(key, seed);

      type = Safe.TYPE_MASTER;
      key = master;
    }

    WeierstrassCurve curve = null;

    if (Safe.isTypeMaster(type)) {
      if (key.length != MASTER_LENGTH) {
        KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
        return null;
      }

      curve = WeierstrassCurve.requireSharedCurve(curveName);
      key = LibBIP32.derive(curve, key, path);
      type = Safe.TYPE_WEIERSTRASS;
    }

    switch (type) {
      case Safe.TYPE_WEIERSTRASS_SECP256K1:
        curve = WeierstrassCurve.secp256k1;
        break;
    }

    Key privateKey;

    switch (type & Safe.TYPE_CATEGORY_MASK) {
      case Safe.TYPE_WEIERSTRASS:
        if (curve == null) {
          KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
        }

        privateKey = curve.getSharedPrivateKey(key, (short) 0);

        break;
      default:
        KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
        return null;
    }

    return Signer.signECDSADigest(Signer.CIPHER_ECDSA, privateKey, digest);
  }

  public byte[] signEDDSAMessage(
    byte[] index,
    byte[] seed,
    byte[] curveName,
    byte[] path,
    ByteSource message,
    short messageOffset,
    short messageLength
  ) throws KeystoreException, CurveException, SignerException {
    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    byte[] key = requireKey(index);

    if (Safe.isTypeSeed(type)) {
      key = deriveMasterFromSeed(key, seed);
      type = Safe.TYPE_MASTER;
    }

    EdwardsCurve curve;

    if (Safe.isTypeMaster(type)) {
      if (key.length != MASTER_LENGTH) {
        KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
        return null;
      }

      curve = EdwardsCurve.requireSharedCurve(curveName);

      LibSLIP10Ed25519.derive(
        key,
        (short) 0,
        (short) key.length,
        path,
        (short) 0,
        (short) path.length,
        key,
        (short) 0
      );
    } else if (type == Safe.TYPE_EDWARDS_ED25519 && key.length == CurveED25519.KEY_LENGTH) {
      curve = EdwardsCurve.ed25519;
    } else {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    ED25519Key privateKey = curve.getSharedPrivateKey(key, (short) 0);

    try {
      return Signer.signEDDSAMessage(curve, privateKey, message, messageOffset, messageLength);
    } finally {
      privateKey.clear();
    }
  }

  private byte[] deriveMasterFromSeed(byte[] key, byte[] seed) {
    switch (key.length) {
      case SEED_512_LENGTH:
        return LibHMACSha512.digest(seed, key);
      default:
        KeystoreException.throwIt(KeystoreException.REASON_UNSUPPORTED_SEED_LENGTH);
        return null;
    }
  }

  private byte[] derivePublicKeyAndChainCodeFromMaster(
    WeierstrassCurve curve,
    byte[] master,
    byte[] path
  ) {
    master = LibBIP32.derive(curve, master, path);

    ECPrivateKey privateKey = curve.getSharedPrivateKey(master, (short) 0);

    byte[] publicKey = curve.derivePublicKey(privateKey);

    short keyLength = curve.getKeyLength();

    byte[] data = JCSystem.makeTransientByteArray(
      (short) (publicKey.length + keyLength),
      JCSystem.CLEAR_ON_DESELECT
    );

    // public key
    Util.arrayCopyNonAtomic(publicKey, (short) 0, data, (short) 0, (short) publicKey.length);
    // chain code
    Util.arrayCopyNonAtomic(master, keyLength, data, (short) publicKey.length, keyLength);

    return data;
  }

  private byte[] derivePublicKeyAndChainCodeFromMaster(
    EdwardsCurve curve,
    byte[] master,
    byte[] path
  ) {
    LibSLIP10Ed25519.derive(
      master,
      (short) 0,
      (short) master.length,
      path,
      (short) 0,
      (short) path.length,
      master,
      (short) 0
    );
    ED25519Key privateKey = curve.getSharedPrivateKey(master, (short) 0);

    try {
      short publicKeyLength = curve.getPublicKeyLength();
      short keyLength = curve.getKeyLength();

      byte[] data = JCSystem.makeTransientByteArray(
        (short) (publicKeyLength + keyLength),
        JCSystem.CLEAR_ON_DESELECT
      );

      curve.derivePublicKey(privateKey, data, (short) 0);
      Util.arrayCopyNonAtomic(master, keyLength, data, publicKeyLength, keyLength);

      return data;
    } finally {
      privateKey.clear();
    }
  }

  private byte[] requireKey(byte[] index) {
    return safe.require(index).getData();
  }
}
