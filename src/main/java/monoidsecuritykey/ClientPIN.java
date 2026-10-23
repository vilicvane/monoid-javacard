package monoidsecuritykey;

import static monoidsecuritykey.Constants.SAFE_FALSE;
import static monoidsecuritykey.Constants.SAFE_TRUE;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
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
import monoidlib.LibSecurity;

/** CTAP 2.0 ClientPIN protocol 1. */
public final class ClientPIN {

  private static final byte PIN_TRY_LIMIT = 8;
  private static final short HASH_LENGTH = 16;
  private static final short TOKEN_LENGTH = 32;
  private static final short PADDED_PIN_LENGTH = 64;
  private static final short PIN_FAILURES = 2;
  private static final short AUTH_FAILURES = 3;
  private static final byte[] ZERO_IV = new byte[16];

  private OwnerPIN pin = new OwnerPIN(PIN_TRY_LIMIT, (byte) HASH_LENGTH);
  private short pinState = SAFE_FALSE;
  private short pinStateInverse = SAFE_TRUE;

  private final short[] session = JCSystem.makeTransientShortArray(
    (short) 4,
    JCSystem.CLEAR_ON_RESET
  );
  private final byte[] token = JCSystem.makeTransientByteArray(
    TOKEN_LENGTH,
    JCSystem.CLEAR_ON_RESET
  );
  private final byte[] sharedSecret = JCSystem.makeTransientByteArray(
    TOKEN_LENGTH,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final byte[] workspace = JCSystem.makeTransientByteArray(
    PADDED_PIN_LENGTH,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final byte[] hmacBlock = JCSystem.makeTransientByteArray(
    LibHMACSha256.BLOCK_LENGTH,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final byte[] receivedAuth = JCSystem.makeTransientByteArray(
    HASH_LENGTH,
    JCSystem.CLEAR_ON_DESELECT
  );

  private final KeyPair keyAgreement;
  private final KeyAgreement agreement = KeyAgreement.getInstance(
    KeyAgreement.ALG_EC_SVDP_DH_PLAIN,
    false
  );
  private final AESKey encryptionKey = (AESKey) KeyBuilder.buildKey(
    KeyBuilder.ALG_TYPE_AES,
    JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT,
    KeyBuilder.LENGTH_AES_256,
    false
  );
  private final Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
  private final MessageDigest digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
  private final RandomData random = RandomData.getInstance(RandomData.ALG_KEYGENERATION);

  private final LibSecurity.Condition pinSetValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      short state = pinState;

      if ((state != SAFE_FALSE && state != SAFE_TRUE) || pinStateInverse != (short) ~state) {
        ISOException.throwIt(CTAP.OTHER);
      }

      return state == SAFE_TRUE;
    }
  };

  private final LibSecurity.Condition pinValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return pin.isValidated();
    }
  };

  private final LibSecurity.Condition pinBlockedValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      return pin.getTriesRemaining() == 0;
    }
  };

  private final LibSecurity.Condition authValidation = new LibSecurity.Condition() {
    @Override
    public boolean check() {
      short difference = 0;

      for (short index = 0; index < HASH_LENGTH; index++) {
        difference |= workspace[index] ^ receivedAuth[index];
      }

      return difference == 0;
    }
  };

  public ClientPIN() {
    // The transient session marker rotates this persistent key after every card reset.
    ECPrivateKey privateKey = (ECPrivateKey) KeyBuilder.buildKey(
      KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
      JCSystem.MEMORY_TYPE_PERSISTENT,
      KeyBuilder.LENGTH_EC_FP_256,
      false
    );
    ECPublicKey publicKey = (ECPublicKey) KeyBuilder.buildKey(
      KeyBuilder.TYPE_EC_FP_PUBLIC,
      KeyBuilder.LENGTH_EC_FP_256,
      false
    );
    LibSECP256r1.initialize(privateKey);
    LibSECP256r1.initialize(publicKey);
    keyAgreement = new KeyPair(publicKey, privateKey);
  }

  public boolean isSet() {
    return LibSecurity.check(pinSetValidation, SAFE_TRUE) != SAFE_FALSE;
  }

  public byte getRetries() {
    return pin.getTriesRemaining();
  }

  public short getKeyAgreement(byte[] dest, short offset) {
    initializeSession();
    return ((ECPublicKey) keyAgreement.getPublic()).getW(dest, offset);
  }

  public void setPIN(byte[] peer, byte[] pinAuth, byte[] newPinEnc) {
    if (isSet()) {
      ISOException.throwIt(CTAP.PIN_AUTH_INVALID);
    }

    agree(peer);
    assertAuth(sharedSecret, pinAuth, newPinEnc, null);
    decryptNewPIN(newPinEnc);
    updatePIN(false);
  }

  public void changePIN(byte[] peer, byte[] pinAuth, byte[] newPinEnc, byte[] pinHashEnc) {
    assertUsablePIN();
    agree(peer);
    assertAuth(sharedSecret, pinAuth, newPinEnc, pinHashEnc);

    try {
      checkPIN(pinHashEnc);
      decryptNewPIN(newPinEnc);
      updatePIN(true);
    } finally {
      pin.reset();
    }
  }

  public short getPINToken(byte[] peer, byte[] pinHashEnc, byte[] dest, short offset) {
    assertUsablePIN();
    agree(peer);
    return encryptToken(pinHashEnc, (short) 0, (short) pinHashEnc.length, dest, offset);
  }

  short getPINToken(
    byte[] peer,
    short peerOffset,
    byte[] pinHashEnc,
    short hashOffset,
    byte[] dest,
    short offset
  ) {
    assertUsablePIN();
    agree(peer, peerOffset, (short) 65);
    return encryptToken(pinHashEnc, hashOffset, HASH_LENGTH, dest, offset);
  }

  private short encryptToken(
    byte[] pinHashEnc,
    short hashOffset,
    short hashLength,
    byte[] dest,
    short offset
  ) {
    try {
      checkPIN(pinHashEnc, hashOffset, hashLength);
      assertValidatedPIN();
      cipher.init(encryptionKey, Cipher.MODE_ENCRYPT, ZERO_IV, (short) 0, (short) ZERO_IV.length);
      return cipher.doFinal(token, (short) 0, TOKEN_LENGTH, dest, offset);
    } finally {
      pin.reset();
    }
  }

  public void verify(byte[] pinAuth, byte[] clientDataHash) {
    assertUsablePIN();
    initializeSession();

    if (clientDataHash.length != TOKEN_LENGTH) {
      ISOException.throwIt(CTAP.INVALID_LENGTH);
    }

    try {
      assertAuth(token, pinAuth, clientDataHash, null);
    } catch (ISOException exception) {
      if (exception.getReason() == CTAP.PIN_AUTH_INVALID) {
        session[AUTH_FAILURES]++;
        assertSessionUnblocked();
      }

      throw exception;
    }

    session[AUTH_FAILURES] = 0;
  }

  public void reset() {
    OwnerPIN nextPIN = new OwnerPIN(PIN_TRY_LIMIT, (byte) HASH_LENGTH);
    boolean ownTransaction = JCSystem.getTransactionDepth() == 0;

    if (ownTransaction) {
      JCSystem.beginTransaction();
    }

    try {
      pin = nextPIN;
      pinState = SAFE_FALSE;
      pinStateInverse = SAFE_TRUE;
      if (ownTransaction) {
        JCSystem.commitTransaction();
      }
    } finally {
      if (ownTransaction && JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }

    session[0] = 0;
    session[1] = 0;
    session[PIN_FAILURES] = 0;
    session[AUTH_FAILURES] = 0;
    deselect();
    if (ownTransaction) {
      JCSystem.requestObjectDeletion();
    }
  }

  public void deselect() {
    pin.reset();
    encryptionKey.clearKey();
    digest.reset();
    // A SELECT must not renew the power-cycle retry budget or PIN token.
  }

  private void initializeSession() {
    if (session[0] == 0 && session[1] == 0) {
      generateKeyAgreement();
      random.nextBytes(token, (short) 0, TOKEN_LENGTH);
      session[1] = SAFE_FALSE;
      session[0] = SAFE_TRUE;
    }

    if (session[0] != SAFE_TRUE || session[1] != SAFE_FALSE) {
      ISOException.throwIt(CTAP.OTHER);
    }
  }

  private void agree(byte[] peer) {
    agree(peer, (short) 0, (short) peer.length);
  }

  private void agree(byte[] peer, short offset, short length) {
    if (length != 65 || peer[offset] != 0x04) {
      ISOException.throwIt(CTAP.INVALID_PARAMETER);
    }

    initializeSession();

    try {
      agreement.init(keyAgreement.getPrivate());
      short secretLength = agreement.generateSecret(peer, offset, length, workspace, (short) 0);

      if (secretLength != TOKEN_LENGTH) {
        ISOException.throwIt(CTAP.OTHER);
      }

      digest.doFinal(workspace, (short) 0, TOKEN_LENGTH, sharedSecret, (short) 0);
      encryptionKey.setKey(sharedSecret, (short) 0);
    } catch (CryptoException exception) {
      ISOException.throwIt(CTAP.INVALID_PARAMETER);
    }
  }

  private void generateKeyAgreement() {
    LibSECP256r1.initialize((ECPrivateKey) keyAgreement.getPrivate());
    keyAgreement.genKeyPair();
  }

  private void assertAuth(byte[] key, byte[] pinAuth, byte[] first, byte[] second) {
    if (pinAuth.length != HASH_LENGTH) {
      ISOException.throwIt(CTAP.PIN_AUTH_INVALID);
    }

    LibHMACSha256.begin(digest, hmacBlock, key, (short) 0, TOKEN_LENGTH);
    digest.update(first, (short) 0, (short) first.length);

    if (second != null) {
      digest.update(second, (short) 0, (short) second.length);
    }

    digest.doFinal(first, (short) 0, (short) 0, workspace, (short) 0);
    LibHMACSha256.finish(digest, hmacBlock, workspace, (short) 0);
    Util.arrayCopyNonAtomic(pinAuth, (short) 0, receivedAuth, (short) 0, HASH_LENGTH);

    if (LibSecurity.check(authValidation, SAFE_FALSE) != SAFE_TRUE) {
      ISOException.throwIt(CTAP.PIN_AUTH_INVALID);
    }
  }

  private void assertUsablePIN() {
    if (!isSet()) {
      ISOException.throwIt(CTAP.PIN_NOT_SET);
    }

    if (LibSecurity.check(pinBlockedValidation, SAFE_TRUE) != SAFE_FALSE) {
      ISOException.throwIt(CTAP.PIN_BLOCKED);
    }

    assertSessionUnblocked();
  }

  private void assertSessionUnblocked() {
    if (session[PIN_FAILURES] >= 3 || session[AUTH_FAILURES] >= 3) {
      ISOException.throwIt(CTAP.PIN_AUTH_BLOCKED);
    }
  }

  private void checkPIN(byte[] encryptedHash) {
    checkPIN(encryptedHash, (short) 0, (short) encryptedHash.length);
  }

  private void checkPIN(byte[] encryptedHash, short offset, short length) {
    if (length != HASH_LENGTH) {
      ISOException.throwIt(CTAP.INVALID_LENGTH);
    }

    pin.reset();
    cipher.init(encryptionKey, Cipher.MODE_DECRYPT, ZERO_IV, (short) 0, (short) ZERO_IV.length);
    cipher.doFinal(encryptedHash, offset, HASH_LENGTH, workspace, (short) 0);

    if (!pin.check(workspace, (short) 0, (byte) HASH_LENGTH)) {
      session[PIN_FAILURES]++;
      generateKeyAgreement();
      assertUsablePIN();
      ISOException.throwIt(CTAP.PIN_INVALID);
    }

    assertValidatedPIN();
    session[PIN_FAILURES] = 0;
    session[AUTH_FAILURES] = 0;
  }

  private void assertValidatedPIN() {
    if (LibSecurity.check(pinValidation, SAFE_FALSE) != SAFE_TRUE) {
      ISOException.throwIt(CTAP.PIN_AUTH_INVALID);
    }
  }

  private void decryptNewPIN(byte[] encrypted) {
    if (encrypted.length < PADDED_PIN_LENGTH || (encrypted.length & 15) != 0) {
      ISOException.throwIt(CTAP.PIN_POLICY_VIOLATION);
    }

    cipher.init(encryptionKey, Cipher.MODE_DECRYPT, ZERO_IV, (short) 0, (short) ZERO_IV.length);
    // A PIN occupies at most the first 63 bytes, even with longer padding.
    cipher.doFinal(encrypted, (short) 0, PADDED_PIN_LENGTH, workspace, (short) 0);
    short length = 0;

    while (length < PADDED_PIN_LENGTH && workspace[length] != 0) {
      length++;
    }

    if (length == PADDED_PIN_LENGTH || countCharacters(length) < 4) {
      ISOException.throwIt(CTAP.PIN_POLICY_VIOLATION);
    }

    digest.doFinal(workspace, (short) 0, length, workspace, (short) 0);
  }

  private short countCharacters(short length) {
    short count = 0;
    short offset = 0;

    while (offset < length) {
      short first = (short) (workspace[offset] & 0xFF);
      short bytes;

      if (first < 0x80) {
        bytes = 1;
      } else if (first >= 0xC2 && first <= 0xDF) {
        bytes = 2;
      } else if (first >= 0xE0 && first <= 0xEF) {
        bytes = 3;
      } else if (first >= 0xF0 && first <= 0xF4) {
        bytes = 4;
      } else {
        ISOException.throwIt(CTAP.PIN_POLICY_VIOLATION);
        return 0;
      }

      if ((short) (offset + bytes) > length) {
        ISOException.throwIt(CTAP.PIN_POLICY_VIOLATION);
      }

      for (short index = 1; index < bytes; index++) {
        short value = (short) (workspace[(short) (offset + index)] & 0xFF);

        if (
          value < 0x80 ||
          value > 0xBF ||
          (index == 1 &&
            ((first == 0xE0 && value < 0xA0) ||
              (first == 0xED && value > 0x9F) ||
              (first == 0xF0 && value < 0x90) ||
              (first == 0xF4 && value > 0x8F)))
        ) {
          ISOException.throwIt(CTAP.PIN_POLICY_VIOLATION);
        }
      }

      offset += bytes;
      count++;
    }

    return count;
  }

  private void updatePIN(boolean changing) {
    if (changing) {
      assertValidatedPIN();
    } else if (isSet()) {
      ISOException.throwIt(CTAP.PIN_AUTH_INVALID);
    }

    random.nextBytes(token, (short) 0, TOKEN_LENGTH);
    JCSystem.beginTransaction();

    try {
      pin.update(workspace, (short) 0, (byte) HASH_LENGTH);
      pinState = SAFE_TRUE;
      pinStateInverse = SAFE_FALSE;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }

    session[PIN_FAILURES] = 0;
    session[AUTH_FAILURES] = 0;
  }
}
