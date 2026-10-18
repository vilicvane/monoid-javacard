package monoidsafe;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import monoidsafeidentity.SafeIdentityShareable;

/** Authenticated item transfer using an Identity-protected communication key. */
public class ItemCipher {

  public static final short SECRET_LENGTH = 2;

  private static final byte VERSION = 1;
  private static final short ENCRYPTED_KEY_OFFSET = 1;
  private static final short ENCRYPTED_KEY_LENGTH = 113;
  private static final short NONCE_OFFSET = ENCRYPTED_KEY_OFFSET + ENCRYPTED_KEY_LENGTH;
  private static final short NONCE_LENGTH = 12;
  private static final short DATA_OFFSET = NONCE_OFFSET + NONCE_LENGTH;
  private static final short TAG_LENGTH = 16;
  private static final short ENVELOPE_OVERHEAD = DATA_OFFSET + SECRET_LENGTH + TAG_LENGTH;
  private static final short KEY_LENGTH = 32;
  private static final short HASH_LENGTH = 32;
  private static final short HMAC_BLOCK_LENGTH = 64;

  // @formatter:off
  private static final byte[] EMPTY = {};
  private static final byte[] CONTEXT = {'M','o','n','o','i','d',' ','I','t','e','m'};
  private static final byte[] KEY_CONTEXT = {'M','o','n','o','i','d',' ','I','t','e','m',' ','K','e','y'};
  // @formatter:on

  private final RandomData random;
  private final MessageDigest digest;
  private final AESKey encryptionKey;
  private final AESGcmCipher cipher;
  private final byte[] keyBytes;
  private final byte[] hmacBlock;
  private final byte[] suffix;

  private final LibSecurity.Condition tagValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return cipher.verifyTag(keyBytes, (short) 0);
    }
  };

  public ItemCipher() {
    random = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
    digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
    encryptionKey = (AESKey) KeyBuilder.buildKey(
      KeyBuilder.ALG_TYPE_AES,
      JCSystem.MEMORY_TYPE_TRANSIENT_RESET,
      KeyBuilder.LENGTH_AES_128,
      false
    );
    cipher = new AESGcmCipher();
    keyBytes = new byte[KEY_LENGTH];
    hmacBlock = JCSystem.makeTransientByteArray(HMAC_BLOCK_LENGTH, JCSystem.CLEAR_ON_RESET);
    suffix = new byte[2];
  }

  /** Returns version || encrypted key || nonce || ciphertext || tag in a private array. */
  public byte[] encrypt(SafeIdentityShareable identity, SafeItem item, byte[] recipientPublicKey) {
    if (item.data.length > (short) (0x7FFF - ENVELOPE_OVERHEAD)) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    byte[] context = createContext(item.index, item.key, item.alias);
    byte[] communicationKey = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      KEY_LENGTH
    );
    random.nextBytes(communicationKey, (short) 0, KEY_LENGTH);

    byte[] encryptedKey = identity.encryptCommunicationKey(
      recipientPublicKey,
      context,
      communicationKey
    );
    deriveKey(communicationKey, context);

    short length = (short) (item.data.length + ENVELOPE_OVERHEAD);
    short plaintextLength = (short) (SECRET_LENGTH + item.data.length);
    byte[] encryptedData = Utils.makePrivateByteArray(length);
    encryptedData[0] = VERSION;
    Util.arrayCopyNonAtomic(
      encryptedKey,
      (short) 0,
      encryptedData,
      ENCRYPTED_KEY_OFFSET,
      ENCRYPTED_KEY_LENGTH
    );
    random.nextBytes(encryptedData, NONCE_OFFSET, NONCE_LENGTH);
    Util.setShort(encryptedData, DATA_OFFSET, item.secret);
    Util.arrayCopyNonAtomic(
      item.data,
      (short) 0,
      encryptedData,
      (short) (DATA_OFFSET + SECRET_LENGTH),
      (short) item.data.length
    );

    cipher.init(encryptionKey, Cipher.MODE_ENCRYPT, encryptedData, NONCE_OFFSET);
    cipher.doFinal(encryptedData, DATA_OFFSET, plaintextLength, encryptedData, DATA_OFFSET);
    cipher.retrieveTag(encryptedData, (short) (length - TAG_LENGTH));

    return encryptedData;
  }

  /** Returns secret (two bytes) || data only after authenticating the complete item. */
  public byte[] decrypt(
    SafeIdentityShareable identity,
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] senderPublicKey,
    SafeDataShareable encryptedData
  ) {
    short encryptedLength = encryptedData.getLength();

    if (encryptedLength < ENVELOPE_OVERHEAD) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    byte[] context = createContext(index, key, alias);
    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      ENCRYPTED_KEY_LENGTH
    );
    encryptedData.read((short) 0, buffer, (short) 0, (short) 1);

    if (buffer[0] != VERSION) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    encryptedData.read(ENCRYPTED_KEY_OFFSET, buffer, (short) 0, ENCRYPTED_KEY_LENGTH);
    byte[] communicationKey = identity.decryptCommunicationKey(
      Utils.duplicateAsGlobal(senderPublicKey),
      context,
      buffer
    );

    short length = (short) (encryptedLength - DATA_OFFSET - TAG_LENGTH);
    byte[] plaintext = Utils.makePrivateByteArray(length);
    Utils.copy(encryptedData, DATA_OFFSET, plaintext, (short) 0, length, buffer);
    encryptedData.read(NONCE_OFFSET, buffer, (short) 0, NONCE_LENGTH);
    encryptedData.read((short) (encryptedLength - TAG_LENGTH), buffer, NONCE_LENGTH, TAG_LENGTH);

    deriveKey(communicationKey, context);
    cipher.init(encryptionKey, Cipher.MODE_DECRYPT, buffer, (short) 0);
    cipher.doFinal(plaintext, (short) 0, length, plaintext, (short) 0);

    // Key derivation is complete; reuse its workspace without retaining caller arrays.
    Util.arrayCopyNonAtomic(buffer, NONCE_LENGTH, keyBytes, (short) 0, TAG_LENGTH);

    if (LibSecurity.check(tagValidation, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    return plaintext;
  }

  private byte[] createContext(byte[] index, byte[] key, byte[] alias) {
    if (index.length != SafeShareable.INDEX_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    byte[] context = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, HASH_LENGTH);
    digest.reset();
    digest.update(CONTEXT, (short) 0, (short) CONTEXT.length);
    suffix[0] = VERSION;
    digest.update(suffix, (short) 0, (short) 1);
    digest.update(index, (short) 0, SafeShareable.INDEX_LENGTH);
    updateContext(key);
    updateContext(alias);
    digest.doFinal(EMPTY, (short) 0, (short) 0, context, (short) 0);

    return context;
  }

  private void updateContext(byte[] value) {
    // Lengths are unsigned big-endian; 0xFFFF distinguishes null from empty.
    Util.setShort(suffix, (short) 0, value == null ? (short) -1 : (short) value.length);
    digest.update(suffix, (short) 0, (short) 2);

    if (value != null) {
      digest.update(value, (short) 0, (short) value.length);
    }
  }

  private void deriveKey(byte[] communicationKey, byte[] context) {
    // RFC 5869: Extract with empty salt, then one Expand block truncated to 16 bytes.
    beginHmac(EMPTY);
    digest.doFinal(communicationKey, (short) 0, KEY_LENGTH, keyBytes, (short) 0);
    finishHmac();

    beginHmac(keyBytes);
    digest.update(KEY_CONTEXT, (short) 0, (short) KEY_CONTEXT.length);
    digest.update(context, (short) 0, HASH_LENGTH);
    suffix[0] = 1;
    digest.doFinal(suffix, (short) 0, (short) 1, keyBytes, (short) 0);
    finishHmac();
    encryptionKey.setKey(keyBytes, (short) 0);
  }

  private void beginHmac(byte[] key) {
    digest.reset();
    Util.arrayFillNonAtomic(hmacBlock, (short) 0, HMAC_BLOCK_LENGTH, (byte) 0x36);

    // Extract uses the empty salt; Expand uses a 32-byte PRK.
    for (short index = 0; index < key.length; index++) {
      hmacBlock[index] ^= key[index];
    }

    digest.update(hmacBlock, (short) 0, HMAC_BLOCK_LENGTH);
  }

  private void finishHmac() {
    for (short index = 0; index < HMAC_BLOCK_LENGTH; index++) {
      hmacBlock[index] ^= (byte) (0x36 ^ 0x5C);
    }

    digest.update(hmacBlock, (short) 0, HMAC_BLOCK_LENGTH);
    digest.doFinal(keyBytes, (short) 0, HASH_LENGTH, keyBytes, (short) 0);
  }
}
