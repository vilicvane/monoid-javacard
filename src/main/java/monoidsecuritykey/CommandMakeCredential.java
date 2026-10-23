package monoidsecuritykey;

import static monoidsecuritykey.Constants.FORMAT_PACKED;
import static monoidsecuritykey.Constants.KEY_ALG;
import static monoidsecuritykey.Constants.KEY_ID;
import static monoidsecuritykey.Constants.KEY_PUBLIC_KEY;
import static monoidsecuritykey.Constants.KEY_SIG;
import static monoidsecuritykey.Constants.KEY_TYPE;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import monoid.Monoid;
import monoidlib.CBORMap;
import monoidlib.CBORReader;
import monoidlib.CBORWriter;

final class CommandMakeCredential extends Command {

  private final Object[] descriptorFields = { KEY_ID, KEY_TYPE };
  private final CBORMap descriptor = new CBORMap(descriptorFields);
  private final MakeCredentialRequest request = new MakeCredentialRequest();
  private final byte[] rpHash = new byte[32];
  private final byte[] id = new byte[32];
  private Credential registration;

  @Override
  void execute(CBORReader reader, CBORWriter writer) {
    request.read(reader);
    CredentialInput input = request.input;
    byte[] clientDataHash = request.clientDataHash;
    authenticator.hash(
      input.buffer(CredentialInput.RP_ID),
      input.offset(CredentialInput.RP_ID),
      input.length(CredentialInput.RP_ID),
      rpHash
    );
    boolean resident = request.resident();
    boolean verified = authenticator.verifyPIN(
      reader,
      request.pinAuthOffset(),
      request.pinProtocolOffset(),
      clientDataHash,
      true
    );
    if (request.requestedUV() && !verified) {
      ISOException.throwIt(CTAP.UNSUPPORTED_OPTION);
    }

    Monoid monoid = MonoidSecurityKeyApplet.connect();
    authenticator.selectScope(monoid);

    if (request.excludeOffset() != 0) {
      reader.setOffset(request.excludeOffset());
      short count = reader.array();
      for (short index = 0; index < count; index++) {
        descriptor.read(reader);
        short next = reader.getOffset();
        short idOffset = descriptor.requireKey(KEY_ID).bytesOffset();
        short idLength = (short) (reader.getOffset() - idOffset);
        boolean supportedType = descriptor.requireKey(KEY_TYPE).textMatches(KEY_PUBLIC_KEY);
        if (
          supportedType &&
          idLength == 32 &&
          authenticator.credentials.find(monoid, reader.getBuffer(), idOffset, rpHash) != null
        ) {
          ISOException.throwIt(CTAP.CREDENTIAL_EXCLUDED);
        }
        reader.setOffset(next);
      }
    }

    do {
      authenticator.random.nextBytes(id, (short) 0, (short) 32);
    } while (monoid.get(Credential.index(id)) != null);
    byte[] point = APDU.getCurrentAPDUBuffer();
    short contextLength = Credential.writeContext(id, rpHash, point, (short) 0);
    monoid.getMonoid001PublicKey(point, (short) 0, contextLength, point, (short) 0);
    Credential credential = Credential.create(
      id,
      rpHash,
      authenticator.credentials.scope,
      input,
      resident,
      point,
      registration
    );
    if (credential.getLength() <= Credential.READ_BUFFER_LENGTH && credential != registration) {
      // Saving a replacement reads old records into the store's separate workspace.
      registration = credential;
    }

    short authDataLength = authenticator.authData(credential, verified, true, true);
    short signatureLength = authenticator.sign(monoid, credential, authDataLength, clientDataHash);
    authenticator.credentials.save(monoid, credential);

    writer.map((short) 3);
    writer.integer((short) 1);
    writer.text(FORMAT_PACKED);
    writer.integer((short) 2);
    writer.bytes(authenticator.authData, (short) 0, authDataLength);
    writer.integer((short) 3);
    writer.map((short) 2);
    writer.text(KEY_ALG);
    writer.integer((short) -7);
    writer.text(KEY_SIG);
    writer.bytes(authenticator.signature, (short) 0, signatureLength);
  }
}
