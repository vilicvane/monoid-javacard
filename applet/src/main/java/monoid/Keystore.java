package monoid;

import javacard.framework.*;
import javacard.security.*;

import monoidsafe.MonoidSafe;

public final class Keystore {
  public static final byte TYPE_SEED = 0x01;
  public static final byte TYPE_MASTER = 0x02;
  public static final byte TYPE_RAW = 0x03;

  public static final byte SIG_CIPHER_ECDSA = 0x01;

  public static final byte SAFE_INDEX_DIGEST_LENGTH = 8;
  public static final byte SAFE_INDEX_LENGTH = 1 + SAFE_INDEX_DIGEST_LENGTH;

  public static final byte SEED_LENGTH = 64;

  public static final byte MASTER_LENGTH = LibBIP32.COMPONENT_LENGTH * 2;
  public static final byte MASTER_PRIVATE_KEY_OFFSET = SAFE_INDEX_LENGTH;
  public static final byte MASTER_CHAIN_CODE_OFFSET = MASTER_PRIVATE_KEY_OFFSET + LibBIP32.COMPONENT_LENGTH;

  private MonoidSafe safe;

  public Keystore(MonoidSafe safe) {
    this.safe = safe;
  }

  public short createRandomSeed(byte[] out, short outOffset) {
    return createRandom(TYPE_SEED, SEED_LENGTH, out, outOffset);
  }

  public short createRandomMaster(byte[] out, short outOffset) {
    return createRandom(TYPE_MASTER, MASTER_LENGTH, out, outOffset);
  }

  public short createRandomRaw(byte length, byte[] out, short outOffset) {
    return createRandom(TYPE_RAW, length, out, outOffset);
  }

  private short createRandom(byte type, byte length, byte[] out, short outOffset) {
    byte[] buffer = JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);

    RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_KEYGENERATION);
    random.nextBytes(buffer, (short) 0, length);
    random.close();

    return addKey(type, buffer, (short) 0, length, out, outOffset);
  }

  /**
   * @param out key index (1 byte type + 8 bytes digest)
   * @return incremented outOffset
   */
  private short addKey(byte type, byte[] in, short keyOffset, byte keyLength, byte[] out, short outOffset) {
    byte[] digest = JCSystem.makeTransientByteArray((short) MessageDigest.LENGTH_SHA_256, JCSystem.CLEAR_ON_DESELECT);

    OneShot.digest(MessageDigest.ALG_SHA_256, in, keyOffset, keyLength, digest, (short) 0);

    byte[] key = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) (SAFE_INDEX_LENGTH + keyLength));

    key[0] = type;
    Util.arrayCopyNonAtomic(digest, (short) 0, key, (short) 1, SAFE_INDEX_DIGEST_LENGTH);
    Util.arrayCopyNonAtomic(in, keyOffset, key, SAFE_INDEX_LENGTH, keyLength);

    safe.set(key, (short) 0, SAFE_INDEX_LENGTH, (short) key.length);

    out[outOffset++] = type;
    outOffset = Util.arrayCopyNonAtomic(digest, (short) 0, out, outOffset, (short) 8);

    return outOffset;
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

    byte[] data = safe.get(in, indexOffset, SAFE_INDEX_LENGTH);

    if (data == null) {
      KeystoreException.throwIt(KeystoreException.REASON_KEY_NOT_FOUND);
      return 0;
    }

    if (type == TYPE_SEED) {
      byte[] master = JCSystem.makeTransientByteArray(MASTER_LENGTH, JCSystem.CLEAR_ON_DESELECT);

      LibHMACSha512.digest(
          in, seedOffset, seedLength,
          data, (short) 0, (short) data.length,
          master, (short) 0);

      type = TYPE_MASTER;
      data = master;
    }

    Curve curve = Curve.requireSharedCurve(in, curveOffset, curveLength);

    if (type == TYPE_MASTER) {
      if (data.length != MASTER_LENGTH) {
        KeystoreException.throwIt(KeystoreException.REASON_INVALID_PARAMETER);
        return 0;
      }

      LibBIP32.deriveInPlace(curve, data, in, pathOffset, pathLength);

      type = TYPE_RAW;
    }

    if (type != TYPE_RAW) {
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
