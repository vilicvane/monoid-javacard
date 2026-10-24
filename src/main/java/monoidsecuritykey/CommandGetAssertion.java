package monoidsecuritykey;

import static monoidsecuritykey.Constants.KEY_RK;
import static monoidsecuritykey.Constants.KEY_UP;
import static monoidsecuritykey.Constants.KEY_UV;
import static monoidsecuritykey.Constants.SAFE_FALSE;
import static monoidsecuritykey.Constants.SAFE_TRUE;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import monoid.Monoid;
import monoidlib.CBORMap;
import monoidlib.CBORReader;
import monoidlib.CBORWriter;

final class CommandGetAssertion extends Command {

  private static final short POSITION = 0;
  private static final short VERIFIED = 1;
  private static final short PRESENCE = 2;

  private static final short[] FIELDS = { 1, 2, 3, 4, 5, 6, 7 };
  private final Object[] optionFields = { KEY_RK, KEY_UV, KEY_UP };
  private final CBORMap fields = new CBORMap(FIELDS);
  private final CBORMap options = new CBORMap(optionFields);

  private final byte[] rpHash = new byte[32];
  private final byte[] clientDataHash = new byte[32];
  private final byte[] assertionScope = new byte[32];
  private final byte[] statelessId = new byte[32];

  // Only a resident selection continues into GetNextAssertion.
  private final Object[] pending = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final short[] state = JCSystem.makeTransientShortArray(
    (short) 3,
    JCSystem.CLEAR_ON_DESELECT
  );

  void clearAssertion() {
    pending[0] = null;

    state[POSITION] = 0;
    state[VERIFIED] = 0;
    state[PRESENCE] = 0;
  }

  @Override
  void execute(CBORReader reader, CBORWriter writer) {
    readRequest(reader);

    Monoid monoid = MonoidSecurityKeyApplet.connect();
    authenticator.selectScope(monoid);

    short count = fields.key((short) 3) ? reader.array() : 0;

    if (count > 0) {
      respondAllowed(monoid, reader, count, writer);
    } else {
      respondDiscovered(monoid, writer);
    }
  }

  void next(CBORWriter writer) {
    CredentialStore.Selection credentials = (CredentialStore.Selection) pending[0];

    if (credentials == null) {
      ISOException.throwIt(CTAP.NOT_ALLOWED);
    }

    Monoid monoid = MonoidSecurityKeyApplet.connect();
    authenticator.selectScope(monoid);

    if (
      Util.arrayCompare(
        assertionScope,
        (short) 0,
        authenticator.credentials.scope,
        (short) 0,
        (short) assertionScope.length
      ) !=
      0
    ) {
      clearAssertion();
      ISOException.throwIt(CTAP.NOT_ALLOWED);
    }

    // A new APDU obtains fresh handles, so deletion or grant revocation takes effect immediately.
    Credential credential = authenticator.credentials.find(
      monoid,
      credentials.ids,
      credentials.offset(state[POSITION]),
      rpHash
    );

    respond(monoid, credential, credentials.count(), writer, false);
  }

  private void readRequest(CBORReader reader) {
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

    state[VERIFIED] = verified ? SAFE_TRUE : SAFE_FALSE;
    state[PRESENCE] = presence ? SAFE_TRUE : SAFE_FALSE;
  }

  private void respondAllowed(Monoid monoid, CBORReader reader, short count, CBORWriter writer) {
    // An allowList identifies one account; use the first credential this card owns,
    // still validating later descriptors.
    Credential selected = null;
    boolean stateless = false;
    byte[] buffer = reader.getBuffer();

    for (short index = 0; index < count; index++) {
      short idOffset = authenticator.readDescriptor(reader);

      if (idOffset < 0 || selected != null || stateless) {
        continue;
      }

      if (authenticator.isStatelessId(rpHash, buffer, idOffset)) {
        Util.arrayCopyNonAtomic(buffer, idOffset, statelessId, (short) 0, (short) 32);
        stateless = true;
      } else {
        selected = authenticator.credentials.find(monoid, buffer, idOffset, rpHash);
      }
    }

    if (stateless) {
      respondStateless(monoid, writer);
    } else {
      respond(monoid, selected, (short) 1, writer, true);
    }
  }

  private void respondDiscovered(Monoid monoid, CBORWriter writer) {
    CredentialStore.Selection credentials = authenticator.credentials.discover(monoid, rpHash);
    short count = credentials.count();

    if (count > 1) {
      pending[0] = credentials;
      Util.arrayCopyNonAtomic(
        authenticator.credentials.scope,
        (short) 0,
        assertionScope,
        (short) 0,
        (short) assertionScope.length
      );
    }

    respond(monoid, credentials.takeFirst(), count, writer, true);
  }

  private void respondStateless(Monoid monoid, CBORWriter writer) {
    // The ID tag binds this scope and RP; the derived key needs no stored public key check.
    short authDataLength = authData();
    short signatureLength = authenticator.sign(
      monoid,
      statelessId,
      rpHash,
      authDataLength,
      clientDataHash
    );

    write(writer, null, authDataLength, signatureLength, (short) 0);
    clearAssertion();
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

    short authDataLength = authData();
    short signatureLength = authenticator.sign(monoid, credential, authDataLength, clientDataHash);

    write(writer, credential, authDataLength, signatureLength, first ? count : 0);

    if (++state[POSITION] == count) {
      clearAssertion();
    }
  }

  private short authData() {
    return authenticator.authData(
      rpHash,
      state[VERIFIED] == SAFE_TRUE,
      state[PRESENCE] == SAFE_TRUE
    );
  }

  /** A null credential writes the stateless ID; a count above one is reported to the client. */
  private void write(
    CBORWriter writer,
    Credential credential,
    short authDataLength,
    short signatureLength,
    short count
  ) {
    boolean user = credential != null;

    writer.map((short) (3 + (user ? 1 : 0) + (count > 1 ? 1 : 0)));
    {
      writer.integer((short) 1);
      if (user) {
        credential.writeDescriptor(writer);
      } else {
        LibCOSE.writeDescriptor(writer, statelessId);
      }

      writer.integer((short) 2);
      writer.bytes(authenticator.authData, (short) 0, authDataLength);

      writer.integer((short) 3);
      writer.bytes(authenticator.signature, (short) 0, signatureLength);

      if (user) {
        writer.integer((short) 4);
        credential.writeUser(writer, state[VERIFIED] == SAFE_TRUE);
      }

      if (count > 1) {
        writer.integer((short) 5);
        writer.integer(count);
      }
    }
  }
}
