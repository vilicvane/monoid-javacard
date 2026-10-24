package monoidsecuritykey;

import static monoidsecuritykey.Constants.FORMAT_PACKED;
import static monoidsecuritykey.Constants.KEY_ALG;
import static monoidsecuritykey.Constants.KEY_SIG;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import monoid.Monoid;
import monoidlib.CBORReader;
import monoidlib.CBORWriter;

final class CommandMakeCredential extends Command {

  private final MakeCredentialRequest request = new MakeCredentialRequest();
  private final byte[] rpHash = new byte[32];
  private final byte[] id = new byte[32];
  private Credential registration;

  @Override
  void execute(CBORReader reader, CBORWriter writer) {
    request.read(reader);

    CredentialInput input = request.input;
    authenticator.hash(
      input.buffer(CredentialInput.RP_ID),
      input.offset(CredentialInput.RP_ID),
      input.length(CredentialInput.RP_ID),
      rpHash
    );

    boolean verified = authenticator.verifyPIN(
      reader,
      request.pinAuthOffset(),
      request.pinProtocolOffset(),
      request.clientDataHash,
      true
    );

    if (request.requestedUV() && !verified) {
      ISOException.throwIt(CTAP.UNSUPPORTED_OPTION);
    }

    Monoid monoid = MonoidSecurityKeyApplet.connect();
    authenticator.selectScope(monoid);

    assertNotExcluded(monoid, reader);

    boolean resident = request.resident();
    Credential credential = createCredential(monoid, resident);

    short authDataLength = authenticator.attestedAuthData(credential, verified);
    short signatureLength = authenticator.sign(
      monoid,
      credential,
      authDataLength,
      request.clientDataHash
    );

    // Non-resident IDs authenticate themselves; assertions derive the key without a record.
    if (resident) {
      authenticator.credentials.save(monoid, credential);
    }

    writer.map((short) 3);
    {
      writer.integer((short) 1);
      writer.text(FORMAT_PACKED);

      writer.integer((short) 2);
      writer.bytes(authenticator.authData, (short) 0, authDataLength);

      writer.integer((short) 3);
      writer.map((short) 2);
      {
        writer.text(KEY_ALG);
        writer.integer((short) -7);

        writer.text(KEY_SIG);
        writer.bytes(authenticator.signature, (short) 0, signatureLength);
      }
    }
  }

  private void assertNotExcluded(Monoid monoid, CBORReader reader) {
    if (request.excludeOffset() == 0) {
      return;
    }

    reader.setOffset(request.excludeOffset());

    short count = reader.array();

    for (short index = 0; index < count; index++) {
      short idOffset = authenticator.readDescriptor(reader);

      if (idOffset >= 0 && authenticator.owns(monoid, reader.getBuffer(), idOffset, rpHash)) {
        ISOException.throwIt(CTAP.CREDENTIAL_EXCLUDED);
      }
    }
  }

  private Credential createCredential(Monoid monoid, boolean resident) {
    if (resident) {
      do {
        authenticator.random.nextBytes(id, (short) 0, (short) 32);
      } while (monoid.get(Credential.index(id)) != null);
    } else {
      authenticator.createStatelessId(rpHash, id);
    }

    byte[] point = APDU.getCurrentAPDUBuffer();
    short contextLength = Credential.writeContext(id, rpHash, point, (short) 0);
    monoid.getMonoid001PublicKey(point, (short) 0, contextLength, point, (short) 0);

    Credential credential = Credential.create(
      id,
      rpHash,
      authenticator.credentials.scope,
      request.input,
      point,
      registration
    );

    if (credential.getLength() <= Credential.READ_BUFFER_LENGTH && credential != registration) {
      // Saving a replacement reads old records into the store's separate workspace.
      registration = credential;
    }

    return credential;
  }
}
