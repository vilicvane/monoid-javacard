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

  public short sign(
      byte[] in,
      short indexOffset,
      short curveOffset, byte curveLength,
      short cipherOffset, byte cipherLength,
      short seedOffset, byte seedLength,
      short pathOffset, byte pathLength,
      short digestOffset, byte digestLength,
      byte[] out, short outOffset) throws KeystoreException, CurveException, SignerException {

    byte type = in[indexOffset];

    byte[] data = safe.get(in, indexOffset, Safe.INDEX_LENGTH);

    if (data == null) {
      KeystoreException.throwIt(KeystoreException.REASON_KEY_NOT_FOUND);
      return 0;
    }

    if (type == Safe.TYPE_SEED) {
      byte[] master = JCSystem.makeTransientByteArray(MASTER_LENGTH, JCSystem.CLEAR_ON_DESELECT);

      LibHMACSha512.digest(
          in, seedOffset, seedLength,
          data, (short) 0, (short) data.length,
          master, (short) 0);

      type = Safe.TYPE_MASTER;
      data = master;
    }

    Curve curve = Curve.requireSharedCurve(in, curveOffset, curveLength);

    if (type == Safe.TYPE_MASTER) {
      if (data.length != MASTER_LENGTH) {
        KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
        return 0;
      }

      LibBIP32.deriveInPlace(curve, data, in, pathOffset, pathLength);

      type = Safe.TYPE_RAW;
    }

    if (type != Safe.TYPE_RAW) {
      KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
      return 0;
    }

    Key privateKey = curve.getSharedPrivateKey(data, (short) 0);

    return Signer.sign(
        in, cipherOffset, cipherLength,
        privateKey,
        in, digestOffset, digestLength,
        out, outOffset);
  }
}
