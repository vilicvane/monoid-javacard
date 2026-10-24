package monoid;

import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.Key;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import monoidlib.ByteSource;
import monoidlib.Utils;

public final class Keystore {

  public static final byte SEED_512_LENGTH = 64;

  private Safe safe;

  private BIP32Derivation bip32;
  private SLIP10Ed25519Derivation slip10Ed25519;
  private Monoid001Derivation monoid001;
  private Signature monoid001Signer;
  private byte[] monoid001Signature;
  private HMAC hmac;

  public Keystore(Safe safe) {
    this.safe = safe;

    bip32 = new BIP32Derivation();
    slip10Ed25519 = new SLIP10Ed25519Derivation();
    monoid001 = new Monoid001Derivation();
  }

  HMAC getHmac() {
    if (hmac == null) {
      hmac = new HMAC();
    }

    return hmac;
  }

  public byte[] getBIP32PublicKeyAndChainCodeFromSeed(
    byte[] index,
    WeierstrassCurve curve,
    byte[] path
  ) {
    return getBIP32PublicKeyAndChainCodeFromSeed(index, curve, path, null);
  }

  public byte[] getBIP32PublicKeyAndChainCodeFromSeed(
    byte[] index,
    WeierstrassCurve curve,
    byte[] path,
    byte[] taprootMerkleRoot
  ) {
    short type = Util.getShort(index, Safe.INDEX_TYPE_OFFSET);

    if (!Safe.isTypeSeed(type)) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    byte[] key = requireKey(index);

    if (taprootMerkleRoot != null && path.length % BIP32Derivation.PATH_SEGMENT_LENGTH != 0) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    DerivedKey derived = bip32.deriveFromSeed(curve, key, path);

    return getBIP32PublicKeyAndChainCode(curve, derived, taprootMerkleRoot);
  }

  public byte[] getSLIP10Ed25519PublicKeyAndChainCodeFromSeed(
    byte[] index,
    EdwardsCurve curve,
    byte[] path
  ) {
    short type = Util.getShort(index, Safe.INDEX_TYPE_OFFSET);

    if (!Safe.isTypeSeed(type)) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    byte[] key = requireKey(index);

    DerivedKey derived = slip10Ed25519.deriveFromSeed(key, path);

    return getSLIP10Ed25519PublicKeyAndChainCode(curve, derived);
  }

  public byte[] getMonoid001PublicKeyFromSeed(byte[] index, byte[] context) {
    return getMonoid001DerivedKeyFromSeed(index, context).getPublicKey(WeierstrassCurve.secp256r1);
  }

  // The session holds authorization while these methods read its validated seed snapshot.
  DerivedKey deriveMonoid001Key(byte[] seed, byte[] context) {
    return monoid001.deriveFromSeed(seed, context);
  }

  byte[] getMonoid001UncompressedPublicKey(byte[] seed, byte[] context) {
    return getMonoid001UncompressedPublicKey(deriveMonoid001Key(seed, context));
  }

  byte[] getMonoid001UncompressedPublicKey(DerivedKey derived) {
    return derived.getUncompressedPublicKey((CurveSECP256r1) WeierstrassCurve.secp256r1);
  }

  byte[] signMonoid001ECDSADigest(byte[] seed, byte[] context, byte[] digest) {
    return signMonoid001ECDSADigest(seed, context, digest, (short) 0);
  }

  byte[] signMonoid001ECDSADigest(byte[] seed, byte[] context, byte[] digest, short digestOffset) {
    return signMonoid001ECDSADigest(deriveMonoid001Key(seed, context), digest, digestOffset);
  }

  // The returned buffer is private working storage; only its first 64 bytes are the signature.
  byte[] signMonoid001ECDSADigest(DerivedKey derived, byte[] digest, short digestOffset) {
    WeierstrassCurve curve = WeierstrassCurve.secp256r1;
    Key privateKey = curve.getSharedPrivateKey(derived.key, (short) 0);

    if (monoid001Signer == null) {
      monoid001Signer = Signature.getInstance(
        MessageDigest.ALG_SHA_256,
        Signature.SIG_CIPHER_ECDSA_PLAIN,
        Cipher.PAD_NULL,
        true
      );
    }

    // Reinitialize for every operation, including after another context used the shared key.
    monoid001Signer.init(privateKey, Signature.MODE_SIGN);
    if (monoid001Signature == null) {
      // Some native PLAIN implementations require 72 bytes of capacity but return 64.
      monoid001Signature = new byte[monoid001Signer.getLength()];
    }

    short length = monoid001Signer.signPreComputedHash(
      digest,
      digestOffset,
      MessageDigest.LENGTH_SHA_256,
      monoid001Signature,
      (short) 0
    );
    if (length != 64) {
      CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    }

    LibECDSA.ensureLowS(curve.getR(), monoid001Signature, (short) 0);
    return monoid001Signature;
  }

  private DerivedKey getMonoid001DerivedKeyFromSeed(byte[] index, byte[] context) {
    short type = Util.getShort(index, Safe.INDEX_TYPE_OFFSET);

    if (!Safe.isTypeSeed(type)) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    byte[] seed = requireKey(index);
    return monoid001.deriveFromSeed(seed, context);
  }

  public byte[] getWeierstrassKeyPublicKey(byte[] index) {
    return getWeierstrassKeyPublicKey(index, null);
  }

  public byte[] getWeierstrassKeyPublicKey(byte[] index, byte[] taprootMerkleRoot) {
    short type = Util.getShort(index, Safe.INDEX_TYPE_OFFSET);

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
    short type = Util.getShort(index, Safe.INDEX_TYPE_OFFSET);

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
    byte[] curveName,
    byte[] path,
    byte[] context,
    byte[] digest
  ) throws KeystoreException, CurveException, SignerException {
    short type = Util.getShort(index, Safe.INDEX_TYPE_OFFSET);

    byte[] key = requireKey(index);

    WeierstrassCurve curve = null;

    if (Safe.isTypeSeed(type)) {
      curve = WeierstrassCurve.requireSharedCurve(curveName);
      DerivedKey derived = context == null
        ? bip32.deriveFromSeed(curve, key, path)
        : monoid001.deriveFromSeed(key, context);

      key = derived.getKey();
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

  public byte[] signED25519Message(
    byte[] index,
    byte[] curveName,
    byte[] path,
    ByteSource message,
    short messageOffset,
    short messageLength
  ) throws KeystoreException, CurveException, SignerException {
    short type = Util.getShort(index, Safe.INDEX_TYPE_OFFSET);

    byte[] key = requireKey(index);

    EdwardsCurve curve;
    ED25519Key privateKey;

    if (Safe.isTypeSeed(type)) {
      curve = EdwardsCurve.requireSharedCurve(curveName);

      DerivedKey derived = slip10Ed25519.deriveFromSeed(key, path);
      privateKey = curve.getSharedPrivateKey(derived);
    } else if (type == Safe.TYPE_EDWARDS_ED25519 && key.length == CurveED25519.KEY_LENGTH) {
      curve = EdwardsCurve.ed25519;
      privateKey = curve.getSharedPrivateKey(key, (short) 0);
    } else {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    try {
      return Signer.signED25519Message(curve, privateKey, message, messageOffset, messageLength);
    } finally {
      privateKey.clear();
    }
  }

  public byte[] signBIP340Digest(
    byte[] index,
    byte[] curveName,
    byte[] path,
    byte[] digest,
    byte[] taprootMerkleRoot
  ) throws KeystoreException, CurveException, SignerException {
    short type = Util.getShort(index, Safe.INDEX_TYPE_OFFSET);

    byte[] key = requireKey(index);

    WeierstrassCurve curve;

    if (Safe.isTypeSeed(type)) {
      if (path.length % BIP32Derivation.PATH_SEGMENT_LENGTH != 0) {
        KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
        return null;
      }

      curve = WeierstrassCurve.requireSharedCurve(curveName);
      DerivedKey derived = bip32.deriveFromSeed(curve, key, path);
      key = derived.getKey();
    } else if (type == Safe.TYPE_WEIERSTRASS_SECP256K1 && key.length == CurveSECP256k1.KEY_LENGTH) {
      curve = WeierstrassCurve.secp256k1;
    } else {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    if (taprootMerkleRoot != null) {
      tweakTaprootPrivateKey(curve, key, taprootMerkleRoot);
    }

    return Signer.signBIP340Digest(curve, key, digest);
  }

  private byte[] getBIP32PublicKeyAndChainCode(
    WeierstrassCurve curve,
    DerivedKey key,
    byte[] taprootMerkleRoot
  ) {
    byte[] publicKey = taprootMerkleRoot == null
      ? key.getPublicKey(curve)
      : derivePublicKey(curve, key.getKey(), taprootMerkleRoot);

    short keyLength = curve.getKeyLength();

    byte[] data = new byte[(short) (publicKey.length + keyLength)];

    // public key
    Util.arrayCopyNonAtomic(publicKey, (short) 0, data, (short) 0, (short) publicKey.length);
    // chain code
    Util.arrayCopyNonAtomic(key.key, keyLength, data, (short) publicKey.length, keyLength);

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
      : Utils.duplicateAsPersistent(publicKey, (short) 1, CurveSECP256k1.KEY_LENGTH);
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

  private byte[] getSLIP10Ed25519PublicKeyAndChainCode(EdwardsCurve curve, DerivedKey key) {
    ED25519Key privateKey = curve.getSharedPrivateKey(key);

    try {
      short publicKeyLength = curve.getPublicKeyLength();
      short keyLength = curve.getKeyLength();

      byte[] data = new byte[(short) (publicKeyLength + keyLength)];

      curve.derivePublicKey(privateKey, data, (short) 0);
      Util.arrayCopyNonAtomic(key.key, keyLength, data, publicKeyLength, keyLength);

      return data;
    } finally {
      privateKey.clear();
    }
  }

  private byte[] requireKey(byte[] index) {
    return safe.require(index).getData().duplicateAsPersistent();
  }
}
