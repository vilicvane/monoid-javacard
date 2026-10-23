package monoidsecuritykey;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import monoid.Monoid;
import monoidlib.CBORBufferWriter;
import monoidlib.CBORMap;
import monoidlib.CBORReader;

final class Authenticator {

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

  byte[] hash(byte[] value) {
    byte[] result = new byte[32];
    hash(value, (short) 0, (short) value.length, result);
    return result;
  }

  void hash(byte[] value, short offset, short length, byte[] result) {
    sha256.doFinal(value, offset, length, result, (short) 0);
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
    short contextLength = credential.writeContext(plain, (short) 0);
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

  short authData(Credential credential, boolean verified, boolean presence, boolean attested) {
    short length = attested ? (short) 164 : (short) 37;
    Util.arrayFillNonAtomic(authData, (short) 0, length, (byte) 0);
    credential.copyRPHash(authData, (short) 0);
    authData[32] = (byte) ((presence ? 1 : 0) | (verified ? 4 : 0) | (attested ? 0x40 : 0));
    // No monotonic counter is advertised across restored or copied credential records.
    if (attested) {
      // Self attestation has a zero AAGUID; no manufacturer identity is asserted.
      Util.setShort(authData, (short) 53, (short) 32);
      credential.copyId(authData, (short) 55);
      publicKeyWriter.reset((short) 87);
      credential.writePublicKey(publicKeyWriter);
    }
    return length;
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
