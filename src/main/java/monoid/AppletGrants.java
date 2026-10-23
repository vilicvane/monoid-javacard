package monoid;

import javacard.framework.AID;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.security.MessageDigest;
import monoidlib.LibSecurity;
import monoidlib.Utils;

final class AppletGrants {

  private final Safe safe;
  private AppletGrant[] grants;
  private MessageDigest tokenHash;
  private byte[] tokenDigest;

  AppletGrants(Safe safe) {
    this.safe = safe;
  }

  void assertManagement() {
    safe.checkAccess();
  }

  AppletGrant[] list() {
    assertManagement();
    return grants;
  }

  AppletGrant get(AID caller) {
    if (grants != null && caller != null) {
      for (short index = 0; index < grants.length; index++) {
        AppletGrant grant = grants[index];

        if (caller.equals(grant.aid, (short) 0, (byte) grant.aid.length)) {
          return grant;
        }
      }
    }

    return null;
  }

  boolean contains(AppletGrant grant) {
    if (grants != null) {
      for (short index = 0; index < grants.length; index++) {
        if (grants[index] == grant) {
          return true;
        }
      }
    }

    return false;
  }

  short getTokenValidationResult(AppletGrant grant, byte[] token, short offset) {
    if (tokenHash == null) {
      tokenHash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
    }
    if (tokenDigest == null) {
      tokenDigest = new byte[MessageDigest.LENGTH_SHA_256];
    }

    // No SIO callback occurs between hashing and checking. Only working storage is shared;
    // each session retains its own caller, grant and authentication state.
    tokenHash.reset();
    tokenHash.doFinal(token, offset, MessageDigest.LENGTH_SHA_256, tokenDigest, (short) 0);
    return LibSecurity.check(grant.tokenHash, tokenDigest, Constants.SAFE_FALSE);
  }

  void set(
    byte[] aid,
    short[] types,
    short[] writable,
    AppletGrant.Key[] keys,
    AppletGrant.Seed seed
  ) {
    assertManagement();

    AID clientAID = JCSystem.lookupAID(aid, (short) 0, (byte) aid.length);

    if (clientAID == null) {
      MonoidException.throwIt(MonoidException.CODE_NOT_FOUND);
    }

    Shareable shareable = JCSystem.getAppletShareableInterfaceObject(clientAID, (byte) 0);
    assertManagement();

    if (!(shareable instanceof MonoidClientShareable)) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    }

    byte[] hash = (byte[]) JCSystem.makeGlobalArray(
      JCSystem.ARRAY_TYPE_BYTE,
      MessageDigest.LENGTH_SHA_256
    );
    short length = ((MonoidClientShareable) shareable).getTokenHash(hash, (short) 0);
    assertManagement();

    if (length != MessageDigest.LENGTH_SHA_256) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    }

    short index = find(aid);
    short count = grants == null ? 0 : (short) grants.length;
    short updatedCount = index < 0 ? (short) (count + 1) : count;
    safe.checkStorage((short) (updatedCount * 2 + MessageDigest.LENGTH_SHA_256));

    AppletGrant replacement = new AppletGrant(
      aid,
      Utils.duplicateAsPersistent(hash),
      types,
      writable,
      keys,
      seed
    );
    AppletGrant[] updated = new AppletGrant[updatedCount];

    for (short entry = 0; entry < count; entry++) {
      updated[entry] = grants[entry];
    }

    updated[index < 0 ? count : index] = replacement;
    publish(updated);
  }

  void remove(byte[] aid) {
    assertManagement();
    short index = find(aid);

    if (index < 0) {
      return;
    }

    AppletGrant[] updated = null;

    if (grants.length > 1) {
      short count = (short) (grants.length - 1);
      safe.checkStorage((short) (count * 2));
      updated = new AppletGrant[count];

      for (short entry = 0; entry < count; entry++) {
        updated[entry] = grants[entry < index ? entry : (short) (entry + 1)];
      }
    }

    publish(updated);
  }

  private short find(byte[] aid) {
    if (grants != null) {
      for (short index = 0; index < grants.length; index++) {
        if (Utils.isEqual(grants[index].aid, aid)) {
          return index;
        }
      }
    }

    return -1;
  }

  private void publish(AppletGrant[] updated) {
    JCSystem.beginTransaction();

    try {
      grants = updated;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != 0) {
        JCSystem.abortTransaction();
      }
    }

    JCSystem.requestObjectDeletion();
  }

  /** Called inside Safe's factory-reset transaction. */
  void clear() {
    grants = null;
    tokenHash = null;
    tokenDigest = null;
  }
}
