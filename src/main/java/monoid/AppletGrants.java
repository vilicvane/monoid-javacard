package monoid;

import javacard.framework.AID;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.security.MessageDigest;

final class AppletGrants {

  private final Safe safe;
  private AppletGrant[] grants;

  AppletGrants(Safe safe) {
    this.safe = safe;
  }

  void assertManagement() {
    Command.requireAuth(Command.AUTH_SECRET);

    if (safe.getPINValidationResult() != Constants.SAFE_TRUE) {
      MonoidException.throwIt(MonoidException.CODE_UNAUTHORIZED);
    }
  }

  AppletGrant[] list() {
    assertManagement();
    return grants;
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
  }
}
