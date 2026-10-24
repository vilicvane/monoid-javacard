package monoidsecuritykey;

import static monoidsecuritykey.Constants.KEY_ID;
import static monoidsecuritykey.Constants.KEY_PUBLIC_KEY;
import static monoidsecuritykey.Constants.KEY_TYPE;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import monoid.Monoid;
import monoidlib.CBORBufferWriter;
import monoidlib.CBORMap;
import monoidlib.CBORReader;

final class Authenticator {

  // @formatter:off
  private static final byte[] SCOPE_LABEL = {'m','o','n','o','i','d',' ','f','i','d','o','2',' ','s','c','o','p','e',':',' '};
  private static final byte[] ID_KEY_LABEL = {'m','o','n','o','i','d',' ','f','i','d','o','2',' ','i','d',':',' '};
  // @formatter:on

  static final short ID_NONCE_LENGTH = 16;

  final CredentialStore credentials = new CredentialStore();
  final ClientPIN pin = new ClientPIN();
  final RandomData random = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
  final MessageDigest sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
  final byte[] authData = new byte[164];
  final byte[] signature = new byte[72];
  private final CBORBufferWriter publicKeyWriter = new CBORBufferWriter(
    authData,
    (short) 87,
    CTAP.LIMIT_EXCEEDED
  );
  private final byte[] pinAuth = new byte[16];
  private final Object[] descriptorFields = { KEY_ID, KEY_TYPE };
  private final CBORMap descriptor = new CBORMap(descriptorFields);
  private final byte[] idKey = JCSystem.makeTransientByteArray(
    (short) 32,
    JCSystem.CLEAR_ON_DESELECT
  );

  byte[] hash(byte[] value) {
    byte[] result = new byte[32];
    hash(value, (short) 0, (short) value.length, result);
    return result;
  }

  void hash(byte[] value, short offset, short length, byte[] result) {
    sha256.doFinal(value, offset, length, result, (short) 0);
  }

  void selectScope(Monoid monoid) {
    byte[] buffer = APDU.getCurrentAPDUBuffer();
    short length = (short) (Constants.DERIVATION_CONTEXT.length + 64);

    // A separate purpose, padded to the credential context length, reuses Monoid's frame.
    Util.arrayFillNonAtomic(buffer, (short) 0, length, (byte) 0);
    Util.arrayCopyNonAtomic(SCOPE_LABEL, (short) 0, buffer, (short) 0, (short) SCOPE_LABEL.length);
    monoid.getMonoid001PublicKey(buffer, (short) 0, length, buffer, (short) 0);

    // The scope point is never returned, so the ID key cannot be recovered from the public scope.
    sha256.update(ID_KEY_LABEL, (short) 0, (short) ID_KEY_LABEL.length);
    sha256.doFinal(buffer, (short) 0, (short) 65, idKey, (short) 0);

    sha256.doFinal(buffer, (short) 0, (short) 65, buffer, (short) 0);
    credentials.setScope(buffer, (short) 0);
  }

  /** Reads one credential descriptor; returns its ID offset, or -1 if this card cannot own it. */
  short readDescriptor(CBORReader reader) {
    descriptor.read(reader);
    short next = reader.getOffset();

    short idOffset = descriptor.requireKey(KEY_ID).bytesOffset();
    short idLength = (short) (reader.getOffset() - idOffset);
    boolean supported = descriptor.requireKey(KEY_TYPE).textMatches(KEY_PUBLIC_KEY);

    reader.setOffset(next);
    return supported && idLength == 32 ? idOffset : -1;
  }

  boolean owns(Monoid monoid, byte[] id, short offset, byte[] rpHash) {
    return (
      isStatelessId(rpHash, id, offset) || credentials.find(monoid, id, offset, rpHash) != null
    );
  }

  /** Writes a non-resident ID that this scope and RP can verify without a stored record. */
  void createStatelessId(byte[] rpHash, byte[] id) {
    random.nextBytes(id, (short) 0, ID_NONCE_LENGTH);

    byte[] block = writeIdTag(rpHash, id, (short) 0);
    Util.arrayCopyNonAtomic(
      block,
      LibHMACSha256.BLOCK_LENGTH,
      id,
      ID_NONCE_LENGTH,
      (short) (32 - ID_NONCE_LENGTH)
    );
  }

  boolean isStatelessId(byte[] rpHash, byte[] id, short offset) {
    byte[] block = writeIdTag(rpHash, id, offset);

    byte difference = 0;
    for (short index = 0; index < (short) (32 - ID_NONCE_LENGTH); index++) {
      difference |= (byte) (block[(short) (LibHMACSha256.BLOCK_LENGTH + index)] ^
        id[(short) (offset + ID_NONCE_LENGTH + index)]);
    }

    return difference == 0;
  }

  private byte[] writeIdTag(byte[] rpHash, byte[] id, short offset) {
    // Requests are held in the reader's own buffer, leaving APDU scratch free here.
    byte[] block = APDU.getCurrentAPDUBuffer();

    LibHMACSha256.begin(sha256, block, idKey, (short) 0, (short) idKey.length);
    sha256.update(rpHash, (short) 0, (short) 32);
    sha256.doFinal(id, offset, ID_NONCE_LENGTH, block, LibHMACSha256.BLOCK_LENGTH);
    LibHMACSha256.finish(sha256, block, block, LibHMACSha256.BLOCK_LENGTH);

    return block;
  }

  void assertCredentialKey(Monoid monoid, Credential credential) {
    byte[] expected = APDU.getCurrentAPDUBuffer();
    short contextLength = credential.writeContext(expected, (short) 0);
    monoid.getMonoid001PublicKey(expected, (short) 0, contextLength, expected, (short) 0);
    if (!credential.matchesPublicKey(expected)) {
      ISOException.throwIt(CTAP.NOT_ALLOWED);
    }
  }

  short sign(Monoid monoid, Credential credential, short authDataLength, byte[] clientDataHash) {
    byte[] plain = APDU.getCurrentAPDUBuffer();
    return sign(monoid, credential.writeContext(plain, (short) 0), authDataLength, clientDataHash);
  }

  short sign(Monoid monoid, byte[] id, byte[] rpHash, short authDataLength, byte[] clientDataHash) {
    byte[] plain = APDU.getCurrentAPDUBuffer();
    short contextLength = Credential.writeContext(id, rpHash, plain, (short) 0);

    return sign(monoid, contextLength, authDataLength, clientDataHash);
  }

  private short sign(
    Monoid monoid,
    short contextLength,
    short authDataLength,
    byte[] clientDataHash
  ) {
    byte[] plain = APDU.getCurrentAPDUBuffer();

    sha256.update(authData, (short) 0, authDataLength);
    sha256.doFinal(clientDataHash, (short) 0, (short) 32, plain, contextLength);

    // The DER result owns its bytes before another SIO or response write reuses the APDU buffer.
    monoid.signMonoid001ECDSADigest(
      plain,
      (short) 0,
      contextLength,
      plain,
      contextLength,
      plain,
      (short) 0
    );

    return LibCOSE.signatureDER(plain, signature, (short) 0);
  }

  short authData(byte[] rpHash, boolean verified, boolean presence) {
    Util.arrayFillNonAtomic(authData, (short) 0, (short) 37, (byte) 0);
    Util.arrayCopyNonAtomic(rpHash, (short) 0, authData, (short) 0, (short) 32);
    // No monotonic counter is advertised across restored or copied credentials.
    authData[32] = (byte) ((presence ? 1 : 0) | (verified ? 4 : 0));

    return 37;
  }

  short attestedAuthData(Credential credential, boolean verified) {
    Util.arrayFillNonAtomic(authData, (short) 0, (short) 164, (byte) 0);
    credential.copyRPHash(authData, (short) 0);
    authData[32] = (byte) (0x41 | (verified ? 4 : 0));

    // Self attestation has a zero AAGUID; no manufacturer identity is asserted.
    Util.setShort(authData, (short) 53, (short) 32);
    credential.copyId(authData, (short) 55);

    publicKeyWriter.reset((short) 87);
    credential.writePublicKey(publicKeyWriter);

    return 164;
  }

  boolean verifyPIN(
    CBORMap fields,
    CBORReader reader,
    short authKey,
    short protocolKey,
    byte[] clientDataHash,
    boolean makeCredential
  ) {
    short authValueOffset = fields.key(authKey) ? reader.getOffset() : 0;
    short protocolValueOffset = fields.key(protocolKey) ? reader.getOffset() : 0;
    return verifyPIN(reader, authValueOffset, protocolValueOffset, clientDataHash, makeCredential);
  }

  boolean verifyPIN(
    CBORReader reader,
    short authValueOffset,
    short protocolValueOffset,
    byte[] clientDataHash,
    boolean makeCredential
  ) {
    if (authValueOffset == 0) {
      if (makeCredential && pin.isSet()) {
        ISOException.throwIt(CTAP.PIN_REQUIRED);
      }
      return false;
    }

    reader.setOffset(authValueOffset);
    short authOffset = reader.bytesOffset();
    short authLength = (short) (reader.getOffset() - authOffset);
    if (authLength == 0) {
      ISOException.throwIt(pin.isSet() ? CTAP.PIN_INVALID : CTAP.PIN_NOT_SET);
    }
    if (protocolValueOffset == 0) {
      ISOException.throwIt(CTAP.MISSING_PARAMETER);
    }
    reader.setOffset(protocolValueOffset);
    if (reader.integer() != 1) {
      ISOException.throwIt(CTAP.PIN_AUTH_INVALID);
    }
    if (authLength == 16) {
      Util.arrayCopyNonAtomic(reader.getBuffer(), authOffset, pinAuth, (short) 0, (short) 16);
      pin.verify(pinAuth, clientDataHash);
    } else {
      // Keep ClientPIN's error precedence and authentication-failure budget for wrong lengths.
      reader.setOffset(authValueOffset);
      pin.verify(reader.bytes(), clientDataHash);
    }
    return true;
  }
}
