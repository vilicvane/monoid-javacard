package monoididentity;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/** Authenticated item transfer; communication and Bundle keys remain inside Identity. */
final class ItemCipher {

  private static final byte VERSION_IDENTITY = 1;
  private static final byte VERSION_BUNDLE = 2;
  private static final short INDEX_LENGTH = 10;
  private static final short SECRET_LENGTH = 2;
  private static final short ENCRYPTED_KEY_OFFSET = 1;
  private static final short ENCRYPTED_KEY_LENGTH = CommunicationCipher.ENCRYPTED_KEY_LENGTH;
  private static final short BUNDLE_HASH_OFFSET = 1;
  private static final short BUNDLE_SALT_OFFSET = 33;
  private static final short NONCE_LENGTH = 12;
  private static final short TAG_LENGTH = 16;
  private static final short KEY_LENGTH = 32;
  private static final short HASH_LENGTH = 32;
  private static final short COPY_BUFFER_LENGTH = 64;

  // @formatter:off
  private static final byte[] EMPTY = {};
  private static final byte[] CONTEXT = {'M','o','n','o','i','d',' ','I','t','e','m'};
  private static final byte[] KEY_CONTEXT = {'M','o','n','o','i','d',' ','I','t','e','m',' ','K','e','y'};
  private static final byte[] BUNDLE_CALLER_CONTEXT = {'M','o','n','o','i','d',' ','B','u','n','d','l','e',' ','C','a','l','l','e','r',' ','K','e','y'};
  private static final byte[] BUNDLE_KEY_CONTEXT = {'M','o','n','o','i','d',' ','B','u','n','d','l','e',' ','I','t','e','m',' ','K','e','y'};
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

  ItemCipher(AESGcmCipher cipher) {
    this.cipher = cipher;

    random = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
    digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
    encryptionKey = (AESKey) KeyBuilder.buildKey(
      KeyBuilder.ALG_TYPE_AES,
      JCSystem.MEMORY_TYPE_TRANSIENT_RESET,
      KeyBuilder.LENGTH_AES_128,
      false
    );
    keyBytes = new byte[KEY_LENGTH];
    hmacBlock = JCSystem.makeTransientByteArray(
      LibHMACSha256.BLOCK_LENGTH,
      JCSystem.CLEAR_ON_RESET
    );
    suffix = new byte[2];
  }

  byte[] encrypt(
    CommunicationCipher communication,
    Bundle bundle,
    AID caller,
    byte[] index,
    byte[] key,
    byte[] alias,
    short secret,
    byte[] recipientPublicKey,
    CommunicationDataShareable data
  ) {
    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, COPY_BUFFER_LENGTH);
    byte[] callerBytes = new byte[16];
    byte callerLength = caller.getBytes(callerBytes, (short) 0);
    byte version = bundle == null ? VERSION_IDENTITY : VERSION_BUNDLE;
    short nonceOffset = nonceOffset(version);
    short dataOffset = (short) (nonceOffset + NONCE_LENGTH);
    short overhead = (short) (dataOffset + SECRET_LENGTH + TAG_LENGTH);
    byte[] context = createContext(version, callerBytes, callerLength, index, key, alias);
    recipientPublicKey = CommunicationData.duplicateAsPrivate(recipientPublicKey);
    short dataLength = data.getLength();

    if (dataLength < 0 || dataLength > (short) (0x7FFF - overhead)) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    short length = (short) (dataLength + overhead);
    byte[] encryptedData = CommunicationData.makePrivateByteArray(length);
    encryptedData[0] = version;

    if (bundle == null) {
      byte[] communicationKey = CommunicationData.makePrivateByteArray(KEY_LENGTH);
      random.nextBytes(communicationKey, (short) 0, KEY_LENGTH);
      byte[] encryptedKey = communication.encrypt(recipientPublicKey, context, communicationKey);
      Util.arrayCopyNonAtomic(
        encryptedKey,
        (short) 0,
        encryptedData,
        ENCRYPTED_KEY_OFFSET,
        ENCRYPTED_KEY_LENGTH
      );
      deriveKey(communicationKey, context, EMPTY, (short) 0, (short) 0, KEY_CONTEXT);
    } else {
      Util.arrayCopyNonAtomic(
        bundle.hash,
        (short) 0,
        encryptedData,
        BUNDLE_HASH_OFFSET,
        HASH_LENGTH
      );
      random.nextBytes(encryptedData, BUNDLE_SALT_OFFSET, KEY_LENGTH);
      deriveBundleCallerKey(bundle.key, callerBytes, callerLength);
      deriveKey(
        keyBytes,
        context,
        encryptedData,
        BUNDLE_SALT_OFFSET,
        KEY_LENGTH,
        BUNDLE_KEY_CONTEXT
      );
    }

    random.nextBytes(encryptedData, nonceOffset, NONCE_LENGTH);
    Util.setShort(encryptedData, dataOffset, secret);
    CommunicationData.copy(
      data,
      (short) 0,
      encryptedData,
      (short) (dataOffset + SECRET_LENGTH),
      dataLength,
      buffer
    );

    cipher.init(encryptionKey, Cipher.MODE_ENCRYPT, encryptedData, nonceOffset);
    cipher.doFinal(
      encryptedData,
      dataOffset,
      (short) (SECRET_LENGTH + dataLength),
      encryptedData,
      dataOffset
    );
    cipher.retrieveTag(encryptedData, (short) (length - TAG_LENGTH));

    return encryptedData;
  }

  byte[] decrypt(
    CommunicationCipher communication,
    Bundle bundle,
    AID caller,
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] senderPublicKey,
    CommunicationDataShareable encryptedData
  ) {
    byte[] buffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, COPY_BUFFER_LENGTH);
    byte[] callerBytes = new byte[16];
    byte callerLength = caller.getBytes(callerBytes, (short) 0);
    index = CommunicationData.duplicateAsPrivate(index);
    key = CommunicationData.duplicateAsPrivate(key);
    alias = CommunicationData.duplicateAsPrivate(alias);
    senderPublicKey = CommunicationData.duplicateAsPrivate(senderPublicKey);
    short encryptedLength = encryptedData.getLength();

    if (encryptedLength < 1) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    encryptedData.read((short) 0, buffer, (short) 0, (short) 1);
    byte version = buffer[0];
    short nonceOffset = nonceOffset(version);
    short dataOffset = (short) (nonceOffset + NONCE_LENGTH);

    if (encryptedLength < (short) (dataOffset + SECRET_LENGTH + TAG_LENGTH)) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    byte[] context = createContext(version, callerBytes, callerLength, index, key, alias);

    if (version == VERSION_IDENTITY) {
      byte[] encryptedKey = CommunicationData.makePrivateByteArray(ENCRYPTED_KEY_LENGTH);
      CommunicationData.copy(
        encryptedData,
        ENCRYPTED_KEY_OFFSET,
        encryptedKey,
        (short) 0,
        ENCRYPTED_KEY_LENGTH,
        buffer
      );
      byte[] communicationKey = communication.decrypt(senderPublicKey, context, encryptedKey);
      deriveKey(communicationKey, context, EMPTY, (short) 0, (short) 0, KEY_CONTEXT);
    } else {
      if (bundle == null) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }

      encryptedData.read(BUNDLE_HASH_OFFSET, buffer, (short) 0, (short) (HASH_LENGTH + KEY_LENGTH));

      if (Util.arrayCompare(bundle.hash, (short) 0, buffer, (short) 0, HASH_LENGTH) != 0) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }

      deriveBundleCallerKey(bundle.key, callerBytes, callerLength);
      deriveKey(keyBytes, context, buffer, HASH_LENGTH, KEY_LENGTH, BUNDLE_KEY_CONTEXT);
    }

    short length = (short) (encryptedLength - dataOffset - TAG_LENGTH);
    byte[] plaintext = CommunicationData.makePrivateByteArray(length);
    CommunicationData.copy(encryptedData, dataOffset, plaintext, (short) 0, length, buffer);
    encryptedData.read(nonceOffset, buffer, (short) 0, NONCE_LENGTH);
    encryptedData.read((short) (encryptedLength - TAG_LENGTH), buffer, NONCE_LENGTH, TAG_LENGTH);
    cipher.init(encryptionKey, Cipher.MODE_DECRYPT, buffer, (short) 0);
    cipher.doFinal(plaintext, (short) 0, length, plaintext, (short) 0);
    Util.arrayCopyNonAtomic(buffer, NONCE_LENGTH, keyBytes, (short) 0, TAG_LENGTH);

    if (LibSecurity.check(tagValidation, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    return plaintext;
  }

  private short nonceOffset(byte version) {
    switch (version) {
      case VERSION_IDENTITY:
        return (short) (ENCRYPTED_KEY_OFFSET + ENCRYPTED_KEY_LENGTH);
      case VERSION_BUNDLE:
        return (short) (BUNDLE_SALT_OFFSET + KEY_LENGTH);
      default:
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        return 0;
    }
  }

  private byte[] createContext(
    byte version,
    byte[] caller,
    byte callerLength,
    byte[] index,
    byte[] key,
    byte[] alias
  ) {
    if (index.length != INDEX_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    byte[] context = CommunicationData.makePrivateByteArray(HASH_LENGTH);
    digest.reset();
    digest.update(CONTEXT, (short) 0, (short) CONTEXT.length);
    suffix[0] = version;
    digest.update(suffix, (short) 0, (short) 1);
    suffix[0] = callerLength;
    digest.update(suffix, (short) 0, (short) 1);
    digest.update(caller, (short) 0, callerLength);
    digest.update(index, (short) 0, INDEX_LENGTH);
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

  private void deriveKey(
    byte[] key,
    byte[] context,
    byte[] salt,
    short saltOffset,
    short saltLength,
    byte[] label
  ) {
    LibHMACSha256.begin(digest, hmacBlock, salt, saltOffset, saltLength);
    digest.doFinal(key, (short) 0, KEY_LENGTH, keyBytes, (short) 0);
    LibHMACSha256.finish(digest, hmacBlock, keyBytes, (short) 0);
    LibHMACSha256.begin(digest, hmacBlock, keyBytes, (short) 0, KEY_LENGTH);
    digest.update(label, (short) 0, (short) label.length);
    digest.update(context, (short) 0, HASH_LENGTH);
    suffix[0] = 1;
    digest.doFinal(suffix, (short) 0, (short) 1, keyBytes, (short) 0);
    LibHMACSha256.finish(digest, hmacBlock, keyBytes, (short) 0);
    encryptionKey.setKey(keyBytes, (short) 0);
  }

  private void deriveBundleCallerKey(byte[] key, byte[] caller, byte callerLength) {
    LibHMACSha256.begin(digest, hmacBlock, key, (short) 0, KEY_LENGTH);
    digest.update(BUNDLE_CALLER_CONTEXT, (short) 0, (short) BUNDLE_CALLER_CONTEXT.length);
    suffix[0] = callerLength;
    digest.update(suffix, (short) 0, (short) 1);
    digest.doFinal(caller, (short) 0, callerLength, keyBytes, (short) 0);
    LibHMACSha256.finish(digest, hmacBlock, keyBytes, (short) 0);
  }
}
