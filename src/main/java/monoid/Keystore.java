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
    return getSeedDerivedPublicKeyAndChainCode(index, seed, curve, path, null);
  }

  public byte[] getSeedDerivedPublicKeyAndChainCode(
    byte[] index,
    byte[] seed,
    WeierstrassCurve curve,
    byte[] path,
    byte[] taprootMerkleRoot
  ) {
    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    if (!Safe.isTypeSeed(type)) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    byte[] key = requireKey(index);

    byte[] master = deriveMasterFromSeed(key, seed);

    return derivePublicKeyAndChainCodeFromMaster(curve, master, path, taprootMerkleRoot);
  }

  public byte[] getMasterDerivedPublicKeyAndChainCode(
    byte[] index,
    WeierstrassCurve curve,
    byte[] path
  ) {
    return getMasterDerivedPublicKeyAndChainCode(index, curve, path, null);
  }

  public byte[] getMasterDerivedPublicKeyAndChainCode(
    byte[] index,
    WeierstrassCurve curve,
    byte[] path,
    byte[] taprootMerkleRoot
  ) {
    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    if (!Safe.isTypeMaster(type)) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    byte[] key = requireKey(index);

    return derivePublicKeyAndChainCodeFromMaster(curve, key, path, taprootMerkleRoot);
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
    return getWeierstrassKeyPublicKey(index, null);
  }

  public byte[] getWeierstrassKeyPublicKey(byte[] index, byte[] taprootMerkleRoot) {
    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    WeierstrassCurve curve;

    switch (type) {
      case Safe.TYPE_WEIERSTRASS_SECP256K1:
        curve = WeierstrassCurve.secp256k1;
        break;
      case Safe.TYPE_WEIERSTRASS_SECP256R1:
        curve = WeierstrassCurve.secp256r1;
        break;
      default:
        KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
        return null;
    }

    byte[] key = requireKey(index);

    return derivePublicKey(curve, key, taprootMerkleRoot);
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
      case Safe.TYPE_WEIERSTRASS_SECP256R1:
        curve = WeierstrassCurve.secp256r1;
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

    return Signer.signECDSADigest(curve, privateKey, digest);
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

  public byte[] signSchnorrDigest(
    byte[] index,
    byte[] seed,
    byte[] curveName,
    byte[] path,
    byte[] digest,
    byte[] taprootMerkleRoot
  ) throws KeystoreException, CurveException, SignerException {
    short type = Util.getShort(index, SafeShareable.INDEX_TYPE_OFFSET);

    byte[] key = requireKey(index);

    if (Safe.isTypeSeed(type)) {
      key = deriveMasterFromSeed(key, seed);
      type = Safe.TYPE_MASTER;
    }

    WeierstrassCurve curve;

    if (Safe.isTypeMaster(type)) {
      if (key.length != MASTER_LENGTH || path.length % LibBIP32.PATH_SEGMENT_LENGTH != 0) {
        KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
        return null;
      }

      curve = WeierstrassCurve.requireSharedCurve(curveName);
      key = LibBIP32.derive(curve, key, path);
    } else if (type == Safe.TYPE_WEIERSTRASS_SECP256K1 && key.length == CurveSECP256k1.KEY_LENGTH) {
      curve = WeierstrassCurve.secp256k1;
    } else {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    if (taprootMerkleRoot != null) {
      tweakTaprootPrivateKey(curve, key, taprootMerkleRoot);
    }

    return Signer.signSchnorrDigest(curve, key, digest);
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
    byte[] path,
    byte[] taprootMerkleRoot
  ) {
    if (
      taprootMerkleRoot != null &&
      (master.length != MASTER_LENGTH || path.length % LibBIP32.PATH_SEGMENT_LENGTH != 0)
    ) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    master = LibBIP32.derive(curve, master, path);

    byte[] publicKey = derivePublicKey(curve, master, taprootMerkleRoot);

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

  private byte[] derivePublicKey(WeierstrassCurve curve, byte[] key, byte[] taprootMerkleRoot) {
    if (taprootMerkleRoot != null) {
      tweakTaprootPrivateKey(curve, key, taprootMerkleRoot);
    }

    ECPrivateKey privateKey = curve.getSharedPrivateKey(key, (short) 0);
    byte[] publicKey = curve.derivePublicKey(privateKey);

    return taprootMerkleRoot == null
      ? publicKey
      : Utils.duplicateAsTransientDeselect(publicKey, (short) 1, CurveSECP256k1.KEY_LENGTH);
  }

  /** Adjusts the operation's key copy in place, preserving any BIP32 chain code. */
  private void tweakTaprootPrivateKey(
    WeierstrassCurve curve,
    byte[] key,
    byte[] taprootMerkleRoot
  ) {
    if (!(curve instanceof CurveSECP256k1)) {
      CurveException.throwIt(CurveException.REASON_UNSUPPORTED_CURVE);
      return;
    }

    if (
      key.length < CurveSECP256k1.KEY_LENGTH ||
      (taprootMerkleRoot.length != 0 && taprootMerkleRoot.length != CurveSECP256k1.KEY_LENGTH)
    ) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return;
    }

    LibBIP341.tweakPrivateKey(
      (CurveSECP256k1) curve,
      key,
      (short) 0,
      taprootMerkleRoot.length == 0 ? null : taprootMerkleRoot,
      (short) 0,
      key,
      (short) 0
    );
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
