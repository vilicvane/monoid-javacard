package monoid;

import javacard.framework.*;
import javacard.security.*;

import monoidsafe.MonoidSafe;

public final class Keystore {
  public static final byte SEED_LENGTH = 64;

  public static final byte MASTER_LENGTH = LibBIP32.COMPONENT_LENGTH * 2;
  public static final byte MASTER_PRIVATE_KEY_OFFSET = Safe.INDEX_LENGTH;
  public static final byte MASTER_CHAIN_CODE_OFFSET = MASTER_PRIVATE_KEY_OFFSET + LibBIP32.COMPONENT_LENGTH;

  private MonoidSafe safe;

  public Keystore(MonoidSafe safe) {
    this.safe = safe;
  }

  public byte[] createRandomSeed() {
    return createRandom(Safe.TYPE_SEED, SEED_LENGTH);
  }

  public byte[] createRandomMaster() {
    return createRandom(Safe.TYPE_MASTER, MASTER_LENGTH);
  }

  public byte[] createRandomRaw(byte length) {
    return createRandom(Safe.TYPE_RAW, length);
  }

  private byte[] createRandom(byte type, byte length) {
    byte[] buffer = JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);

    RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
    random.nextBytes(buffer, (short) 0, length);
    random.close();

    return addKey(type, buffer);
  }

  private byte[] addKey(byte type, byte[] key) {
    byte[] digest = JCSystem.makeTransientByteArray((short) MessageDigest.LENGTH_SHA_256, JCSystem.CLEAR_ON_DESELECT);

    OneShot.digest(MessageDigest.ALG_SHA_256, key, (short) 0, (short) key.length, digest, (short) 0);

    byte[] index = JCSystem.makeTransientByteArray((short) Safe.INDEX_LENGTH, JCSystem.CLEAR_ON_DESELECT);

    index[0] = type;
    Util.arrayCopyNonAtomic(digest, (short) 0, index, (short) 1, Safe.INDEX_DIGEST_LENGTH);

    byte[] data = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) (Safe.INDEX_LENGTH + key.length));

    Util.arrayCopyNonAtomic(index, (short) 0, data, (short) 0, Safe.INDEX_LENGTH);
    Util.arrayCopyNonAtomic(key, (short) 0, data, Safe.INDEX_LENGTH, (short) key.length);

    safe.set(data, (short) 0, Safe.INDEX_LENGTH, (short) data.length);

    return index;
  }

  public byte[] getSeedDerivedPublicKeyAndChainCode(byte[] index, byte[] seed, Curve curve, byte[] path) {
    if (index[0] != Safe.TYPE_SEED) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    byte[] key = requireKey(index);

    byte[] master = deriveMasterFromSeed(key, seed);

    return derivePublicKeyAndChainCodeFromMaster(curve, master, path);
  }

  public byte[] getMasterDerivedPublicKeyAndChainCode(byte[] index, Curve curve, byte[] path) {
    if (index[0] != Safe.TYPE_MASTER) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    byte[] key = requireKey(index);

    return derivePublicKeyAndChainCodeFromMaster(curve, key, path);
  }

  public byte[] getRawPublicKey(byte[] index, Curve curve) {
    if (index[0] != Safe.TYPE_RAW) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    byte[] key = requireKey(index);

    if (key.length != curve.getKeyLength()) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    ECPrivateKey privateKey = curve.getSharedPrivateKey(key, (short) 0);

    return curve.derivePublicKey(privateKey);
  }

  public byte[] sign(
      byte[] index,
      Curve curve,
      byte[] cipher,
      byte[] seed,
      byte[] path,
      byte[] digest) throws KeystoreException, CurveException, SignerException {

    byte type = index[0];

    byte[] key = requireKey(index);

    if (type == Safe.TYPE_SEED) {
      byte[] master = deriveMasterFromSeed(key, seed);

      type = Safe.TYPE_MASTER;
      key = master;
    }

    if (type == Safe.TYPE_MASTER) {
      if (key.length != MASTER_LENGTH) {
        KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
        return null;
      }

      LibBIP32.deriveInPlace(curve, key, path, (short) 0, (short) path.length);

      type = Safe.TYPE_RAW;
    }

    if (type != Safe.TYPE_RAW) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return null;
    }

    Key privateKey = curve.getSharedPrivateKey(key, (short) 0);

    return Signer.sign(cipher, privateKey, digest);
  }

  private byte[] deriveMasterFromSeed(byte[] key, byte[] seed) {
    byte[] master = JCSystem.makeTransientByteArray(MASTER_LENGTH, JCSystem.CLEAR_ON_DESELECT);

    LibHMACSha512.digest(
        seed, (short) 0, (short) seed.length,
        key, (short) 0, (short) key.length,
        master, (short) 0);

    return master;
  }

  private byte[] derivePublicKeyAndChainCodeFromMaster(
      Curve curve,
      byte[] master,
      byte[] path) {
    LibBIP32.deriveInPlace(curve, master, path, (short) 0, (short) path.length);

    ECPrivateKey privateKey = curve.getSharedPrivateKey(master, (short) 0);

    byte[] publicKey = curve.derivePublicKey(privateKey);

    short keyLength = curve.getKeyLength();

    byte[] data = JCSystem.makeTransientByteArray((short) (publicKey.length + keyLength), JCSystem.CLEAR_ON_DESELECT);

    // public key
    Util.arrayCopyNonAtomic(publicKey, (short) 0, data, (short) 0, (short) publicKey.length);
    // chain code
    Util.arrayCopyNonAtomic(master, keyLength, data, (short) publicKey.length, keyLength);

    return data;
  }

  private byte[] requireKey(byte[] index) {
    index = Utils.duplicateAsGlobal(index);

    byte[] key = safe.get(index, (short) 0, Safe.INDEX_LENGTH);

    if (key == null) {
      KeystoreException.throwIt(KeystoreException.REASON_KEY_NOT_FOUND);
      return null;
    }

    return key;
  }
}
