package monoidsafeidentity;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/** RFC 9180 Auth: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. */
public class CommunicationCipher {

  public static final short PUBLIC_KEY_LENGTH = 65;
  public static final short KEY_LENGTH = 32;
  public static final short ENCRYPTED_KEY_LENGTH = PUBLIC_KEY_LENGTH + KEY_LENGTH + 16;

  private static final short TAG_OFFSET = PUBLIC_KEY_LENGTH + KEY_LENGTH;
  private static final short TAG_LENGTH = 16;
  private static final short NONCE_LENGTH = 12;
  private static final short HASH_LENGTH = 32;
  private static final short HMAC_BLOCK_LENGTH = 64;

  // @formatter:off
  private static final byte[] EMPTY = {};
  private static final byte[] VERSION = {'H','P','K','E','-','v','1'};
  private static final byte[] KEM_SUITE = {'K','E','M', 0x00, 0x10};
  private static final byte[] SUITE = {'H','P','K','E', 0x00, 0x10, 0x00, 0x01, 0x00, 0x01};
  private static final byte[] EAE_PRK = {'e','a','e','_','p','r','k'};
  private static final byte[] SHARED_SECRET = {'s','h','a','r','e','d','_','s','e','c','r','e','t'};
  private static final byte[] PSK_ID_HASH = {'p','s','k','_','i','d','_','h','a','s','h'};
  private static final byte[] INFO_HASH = {'i','n','f','o','_','h','a','s','h'};
  private static final byte[] SECRET = {'s','e','c','r','e','t'};
  private static final byte[] KEY = {'k','e','y'};
  private static final byte[] BASE_NONCE = {'b','a','s','e','_','n','o','n','c','e'};
  // @formatter:on

  private KeyPair identity;
  private ECPrivateKey ephemeralPrivateKey;
  private KeyAgreement agreement;
  private RandomData random;
  private MessageDigest digest;
  private AESKey encryptionKey;
  private AESGcmCipher cipher;

  // EC points, the HPKE key schedule context and the expected tag are used in order.
  private byte[] workspace;
  private byte[] dh;
  private byte[] secret;
  private byte[] keyBytes;
  private byte[] hmacBlock;
  private byte[] hmacSuffix;

  private final LibSecurity.Condition tagValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return cipher.verifyTag(workspace, (short) 0);
    }
  };

  public CommunicationCipher(KeyPair identity) {
    this.identity = identity;

    ephemeralPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(
      KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
      JCSystem.MEMORY_TYPE_PERSISTENT,
      KeyBuilder.LENGTH_EC_FP_256,
      false
    );
    LibSECP256r1.initialize(ephemeralPrivateKey);

    encryptionKey = (AESKey) KeyBuilder.buildKey(
      KeyBuilder.ALG_TYPE_AES,
      JCSystem.MEMORY_TYPE_TRANSIENT_RESET,
      KeyBuilder.LENGTH_AES_128,
      false
    );

    // Identity is called through a Shareable while Safe or Monoid is selected.
    agreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, true);
    random = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
    digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
    cipher = new AESGcmCipher();

    workspace = new byte[PUBLIC_KEY_LENGTH];
    dh = new byte[KEY_LENGTH * 2];
    secret = new byte[HASH_LENGTH];
    keyBytes = new byte[KEY_LENGTH];
    hmacBlock = JCSystem.makeTransientByteArray(HMAC_BLOCK_LENGTH, JCSystem.CLEAR_ON_RESET);
    hmacSuffix = new byte[2];
  }

  /** Returns enc || ciphertext || tag in a new global array. */
  public byte[] encrypt(byte[] recipientPublicKey, byte[] context, byte[] key) {
    requirePublicKey(recipientPublicKey, (short) 0, (short) recipientPublicKey.length);

    if (key.length != KEY_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    byte[] encryptedKey = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      ENCRYPTED_KEY_LENGTH
    );

    generateEphemeralKey();
    agree(ephemeralPrivateKey, LibSECP256r1.G, (short) 0);
    Util.arrayCopyNonAtomic(workspace, (short) 0, encryptedKey, (short) 0, PUBLIC_KEY_LENGTH);

    agree(ephemeralPrivateKey, recipientPublicKey, (short) 0);
    Util.arrayCopyNonAtomic(workspace, (short) 1, dh, (short) 0, KEY_LENGTH);
    agree((ECPrivateKey) identity.getPrivate(), recipientPublicKey, (short) 0);
    Util.arrayCopyNonAtomic(workspace, (short) 1, dh, KEY_LENGTH, KEY_LENGTH);

    ((ECPublicKey) identity.getPublic()).getW(workspace, (short) 0);
    extractAndExpand(encryptedKey, recipientPublicKey, workspace);
    deriveKey(context);

    cipher.init(encryptionKey, Cipher.MODE_ENCRYPT, keyBytes, (short) 0);
    cipher.doFinal(key, (short) 0, KEY_LENGTH, encryptedKey, PUBLIC_KEY_LENGTH);
    cipher.retrieveTag(encryptedKey, TAG_OFFSET);

    return encryptedKey;
  }

  /** Releases the recovered key only after authenticating the complete envelope. */
  public byte[] decrypt(byte[] senderPublicKey, byte[] context, byte[] encryptedKey) {
    requirePublicKey(senderPublicKey, (short) 0, (short) senderPublicKey.length);

    if (encryptedKey.length != ENCRYPTED_KEY_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    requirePublicKey(encryptedKey, (short) 0, PUBLIC_KEY_LENGTH);

    agree((ECPrivateKey) identity.getPrivate(), encryptedKey, (short) 0);
    Util.arrayCopyNonAtomic(workspace, (short) 1, dh, (short) 0, KEY_LENGTH);
    agree((ECPrivateKey) identity.getPrivate(), senderPublicKey, (short) 0);
    Util.arrayCopyNonAtomic(workspace, (short) 1, dh, KEY_LENGTH, KEY_LENGTH);

    ((ECPublicKey) identity.getPublic()).getW(workspace, (short) 0);
    extractAndExpand(encryptedKey, workspace, senderPublicKey);
    deriveKey(context);

    // Allocate a fresh result; the caller's envelope never holds unauthenticated plaintext.
    byte[] key = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, KEY_LENGTH);

    cipher.init(encryptionKey, Cipher.MODE_DECRYPT, keyBytes, (short) 0);
    cipher.doFinal(encryptedKey, PUBLIC_KEY_LENGTH, KEY_LENGTH, key, (short) 0);

    // The key schedule context is no longer needed; retain only the expected tag.
    Util.arrayCopyNonAtomic(encryptedKey, TAG_OFFSET, workspace, (short) 0, TAG_LENGTH);

    if (LibSecurity.check(tagValidation, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    return key;
  }

  private void generateEphemeralKey() {
    byte nonzero;

    do {
      random.nextBytes(keyBytes, (short) 0, KEY_LENGTH);
      nonzero = 0;

      for (short index = 0; index < KEY_LENGTH; index++) {
        nonzero |= keyBytes[index];
      }
    } while (
      nonzero == 0 ||
      compareUnsigned(keyBytes, (short) 0, LibSECP256r1.R, (short) 0, KEY_LENGTH) >= 0
    );

    ephemeralPrivateKey.setS(keyBytes, (short) 0, KEY_LENGTH);
  }

  private void requirePublicKey(byte[] publicKey, short offset, short length) {
    if (
      length != PUBLIC_KEY_LENGTH ||
      publicKey[offset] != 0x04 ||
      compareUnsigned(publicKey, (short) (offset + 1), LibSECP256r1.FP, (short) 0, KEY_LENGTH) >=
      0 ||
      compareUnsigned(
        publicKey,
        (short) (offset + 1 + KEY_LENGTH),
        LibSECP256r1.FP,
        (short) 0,
        KEY_LENGTH
      ) >=
      0
    ) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
  }

  private static byte compareUnsigned(
    byte[] a,
    short aOffset,
    byte[] b,
    short bOffset,
    short length
  ) {
    // Util.arrayCompare does not provide unsigned integer ordering on every card.
    for (short index = 0; index < length; index++) {
      short left = (short) (a[(short) (aOffset + index)] & 0xFF);
      short right = (short) (b[(short) (bOffset + index)] & 0xFF);

      if (left != right) {
        return left < right ? (byte) -1 : (byte) 1;
      }
    }

    return 0;
  }

  private void agree(ECPrivateKey privateKey, byte[] publicKey, short offset) {
    // The native ECDH primitive rejects points inconsistent with these P-256 parameters.
    agreement.init(privateKey);
    short length = agreement.generateSecret(
      publicKey,
      offset,
      PUBLIC_KEY_LENGTH,
      workspace,
      (short) 0
    );

    if (length != PUBLIC_KEY_LENGTH || workspace[0] != 0x04) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
  }

  private void extractAndExpand(byte[] enc, byte[] recipient, byte[] sender) {
    labeledExtract(EMPTY, KEM_SUITE, EAE_PRK, dh, secret, (short) 0);
    beginExpand(secret, KEM_SUITE, SHARED_SECRET, HASH_LENGTH);
    digest.update(enc, (short) 0, PUBLIC_KEY_LENGTH);
    digest.update(recipient, (short) 0, PUBLIC_KEY_LENGTH);
    digest.update(sender, (short) 0, PUBLIC_KEY_LENGTH);
    finishExpand(secret);
  }

  private void deriveKey(byte[] context) {
    workspace[0] = 0x02;
    labeledExtract(EMPTY, SUITE, PSK_ID_HASH, EMPTY, workspace, (short) 1);
    labeledExtract(EMPTY, SUITE, INFO_HASH, context, workspace, (short) (1 + HASH_LENGTH));
    labeledExtract(secret, SUITE, SECRET, EMPTY, secret, (short) 0);

    beginExpand(secret, SUITE, KEY, (short) 16);
    digest.update(workspace, (short) 0, (short) workspace.length);
    finishExpand(keyBytes);
    encryptionKey.setKey(keyBytes, (short) 0);

    beginExpand(secret, SUITE, BASE_NONCE, NONCE_LENGTH);
    digest.update(workspace, (short) 0, (short) workspace.length);
    finishExpand(keyBytes);
  }

  private void labeledExtract(
    byte[] salt,
    byte[] suite,
    byte[] label,
    byte[] input,
    byte[] out,
    short offset
  ) {
    beginHmac(salt);
    digest.update(VERSION, (short) 0, (short) VERSION.length);
    digest.update(suite, (short) 0, (short) suite.length);
    digest.update(label, (short) 0, (short) label.length);
    digest.doFinal(input, (short) 0, (short) input.length, out, offset);
    finishHmac(out, offset);
  }

  private void beginExpand(byte[] prk, byte[] suite, byte[] label, short length) {
    beginHmac(prk);
    Util.setShort(hmacSuffix, (short) 0, length);
    digest.update(hmacSuffix, (short) 0, (short) 2);
    digest.update(VERSION, (short) 0, (short) VERSION.length);
    digest.update(suite, (short) 0, (short) suite.length);
    digest.update(label, (short) 0, (short) label.length);
  }

  private void finishExpand(byte[] out) {
    // All outputs are at most SHA-256's length: HKDF-Expand needs only block 1.
    hmacSuffix[0] = 0x01;
    digest.doFinal(hmacSuffix, (short) 0, (short) 1, out, (short) 0);
    finishHmac(out, (short) 0);
  }

  private void beginHmac(byte[] key) {
    digest.reset();
    Util.arrayFillNonAtomic(hmacBlock, (short) 0, HMAC_BLOCK_LENGTH, (byte) 0x36);

    // HPKE's Extract salts and Expand PRKs are empty or exactly 32 bytes.
    for (short index = 0; index < key.length; index++) {
      hmacBlock[index] ^= key[index];
    }

    digest.update(hmacBlock, (short) 0, HMAC_BLOCK_LENGTH);
  }

  private void finishHmac(byte[] out, short offset) {
    for (short index = 0; index < HMAC_BLOCK_LENGTH; index++) {
      hmacBlock[index] ^= (byte) (0x36 ^ 0x5C);
    }

    digest.update(hmacBlock, (short) 0, HMAC_BLOCK_LENGTH);
    digest.doFinal(out, offset, HASH_LENGTH, out, offset);
  }
}
