package monoidsecuritykey;

import static monoidsecuritykey.Constants.KEY_ID;
import static monoidsecuritykey.Constants.KEY_PUBLIC_KEY;
import static monoidsecuritykey.Constants.KEY_RK;
import static monoidsecuritykey.Constants.KEY_TYPE;
import static monoidsecuritykey.Constants.KEY_UP;
import static monoidsecuritykey.Constants.KEY_UV;
import static monoidsecuritykey.Constants.SAFE_FALSE;
import static monoidsecuritykey.Constants.SAFE_TRUE;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import monoid.Monoid;
import monoidlib.CBORMap;
import monoidlib.CBORReader;
import monoidlib.CBORWriter;

final class CommandGetAssertion extends Command {

  private static final short[] FIELDS = { 1, 2, 3, 4, 5, 6, 7 };
  private final Object[] optionFields = { KEY_RK, KEY_UV, KEY_UP };
  private final Object[] descriptorFields = { KEY_ID, KEY_TYPE };
  private final CBORMap fields = new CBORMap(FIELDS);
  private final CBORMap options = new CBORMap(optionFields);
  private final CBORMap descriptor = new CBORMap(descriptorFields);
  private final byte[] rpHash = new byte[32];
  private final byte[] clientDataHash = new byte[32];

  private final Object[] pending = JCSystem.makeTransientObjectArray(
    (short) 3,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final short[] state = JCSystem.makeTransientShortArray(
    (short) 3,
    JCSystem.CLEAR_ON_DESELECT
  );

  void clearAssertion() {
    pending[0] = null;
    pending[1] = null;
    pending[2] = null;
    state[0] = 0;
    state[1] = 0;
    state[2] = 0;
  }

  @Override
  void execute(CBORReader reader, CBORWriter writer) {
    fields.read(reader);
    assertEmpty(reader);
    short rpOffset = fields.requireKey((short) 1).textOffset();
    authenticator.hash(
      reader.getBuffer(),
      rpOffset,
      (short) (reader.getOffset() - rpOffset),
      rpHash
    );
    fields.requireKey((short) 2).bytes(clientDataHash, (short) 0, (short) 32);
    boolean presence = true;
    boolean requestedUV = false;
    if (fields.key((short) 5)) {
      options.read(reader);
      if (options.key(KEY_RK)) {
        ISOException.throwIt(CTAP.INVALID_OPTION);
      }
      presence = !options.key(KEY_UP) || reader.bool();
      requestedUV = options.key(KEY_UV) && reader.bool();
    }
    boolean verified = authenticator.verifyPIN(
      fields,
      reader,
      (short) 6,
      (short) 7,
      clientDataHash,
      false
    );
    if (requestedUV && !verified) {
      ISOException.throwIt(CTAP.UNSUPPORTED_OPTION);
    }

    Monoid monoid = MonoidSecurityKeyApplet.connect();
    Credential selected = null;
    CredentialStore.Selection credentials = null;
    if (fields.key((short) 3)) {
      short count = reader.array();
      if (count > 0) {
        // An allowList identifies one account; return the first credential supported by this card.
        for (short index = 0; index < count; index++) {
          descriptor.read(reader);
          short next = reader.getOffset();
          short idOffset = descriptor.requireKey(KEY_ID).bytesOffset();
          short idLength = (short) (reader.getOffset() - idOffset);
          boolean supported = descriptor.requireKey(KEY_TYPE).textMatches(KEY_PUBLIC_KEY);
          if (selected == null && idLength == 32 && supported) {
            selected = authenticator.credentials.find(monoid, reader.getBuffer(), idOffset, rpHash);
          }
          reader.setOffset(next);
        }
        if (selected == null) {
          ISOException.throwIt(CTAP.NO_CREDENTIALS);
        }
      }
    }
    short count = 1;
    if (selected == null) {
      credentials = authenticator.credentials.discover(monoid, rpHash);
      count = credentials.count();
      if (count == 0) {
        ISOException.throwIt(CTAP.NO_CREDENTIALS);
      }
      selected = credentials.takeFirst();
    }

    pending[0] = count > 1 ? credentials : null;
    pending[1] = clientDataHash;
    pending[2] = rpHash;
    state[0] = 0;
    state[1] = verified ? SAFE_TRUE : SAFE_FALSE;
    state[2] = presence ? SAFE_TRUE : SAFE_FALSE;
    respond(monoid, selected, count, writer, true);
  }

  void next(CBORWriter writer) {
    if (pending[0] == null) {
      ISOException.throwIt(CTAP.NOT_ALLOWED);
    }
    Monoid monoid = MonoidSecurityKeyApplet.connect();
    CredentialStore.Selection credentials = (CredentialStore.Selection) pending[0];
    // A new APDU obtains fresh handles, so deletion or grant revocation takes effect immediately.
    Credential credential = authenticator.credentials.find(
      monoid,
      credentials.ids,
      credentials.offset(state[0]),
      (byte[]) pending[2]
    );
    respond(monoid, credential, credentials.count(), writer, false);
  }

  private void respond(
    Monoid monoid,
    Credential credential,
    short count,
    CBORWriter writer,
    boolean first
  ) {
    if (credential == null) {
      clearAssertion();
      ISOException.throwIt(CTAP.NO_CREDENTIALS);
    }
    authenticator.assertCredentialKey(monoid, credential);
    boolean verified = state[1] == SAFE_TRUE;
    short authDataLength = authenticator.authData(
      credential,
      verified,
      state[2] == SAFE_TRUE,
      false
    );
    short signatureLength = authenticator.sign(
      monoid,
      credential,
      authDataLength,
      (byte[]) pending[1]
    );
    boolean multiple = first && count > 1;
    writer.map((short) (3 + (credential.resident() ? 1 : 0) + (multiple ? 1 : 0)));
    writer.integer((short) 1);
    credential.writeDescriptor(writer);
    writer.integer((short) 2);
    writer.bytes(authenticator.authData, (short) 0, authDataLength);
    writer.integer((short) 3);
    writer.bytes(authenticator.signature, (short) 0, signatureLength);
    if (credential.resident()) {
      writer.integer((short) 4);
      credential.writeUser(writer, verified);
    }
    if (multiple) {
      writer.integer((short) 5);
      writer.integer(count);
    }
    if (++state[0] == count) {
      clearAssertion();
    }
  }
}
