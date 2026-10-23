package monoidsecuritykey;

import static monoidsecuritykey.Constants.CREDENTIAL_TYPE;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import monoid.Monoid;
import monoid.SafeDataShareable;
import monoid.SafeItemIteratorShareable;
import monoid.SafeItemShareable;
import monoidlib.Utils;

final class CredentialStore {

  static final short DISCOVERY_CAPACITY = 4;

  final byte[] scope = new byte[32];

  private Credential workspace;
  private Credential largeWorkspace;
  private final Credential[] cached = new Credential[DISCOVERY_CAPACITY];
  private final SafeDataShareable[] sources = new SafeDataShareable[DISCOVERY_CAPACITY];
  private short nextCache;
  private final byte[] lookupIndex = new byte[10];
  private final byte[] lookupKey = new byte[64];
  private final byte[] indices = new byte[DISCOVERY_CAPACITY * 10];
  private final Selection selection = new Selection(new byte[DISCOVERY_CAPACITY * 32]);

  CredentialStore() {
    for (short slot = 0; slot < DISCOVERY_CAPACITY; slot++) {
      cached[slot] = Credential.cached();
    }
  }

  Credential find(Monoid monoid, byte[] id, byte[] rpHash) {
    if (id.length != 32) {
      return null;
    }
    return find(monoid, id, (short) 0, rpHash);
  }

  Credential find(Monoid monoid, byte[] id, short offset, byte[] rpHash) {
    Util.setShort(lookupIndex, (short) 0, CREDENTIAL_TYPE);
    Util.arrayCopyNonAtomic(id, offset, lookupIndex, (short) 2, (short) 8);
    writeLookupKey(rpHash);

    Credential credential = readCached(monoid, lookupIndex, (short) 0, lookupKey);
    return credential != null && credential.matchesId(id, offset) ? credential : null;
  }

  void setScope(byte[] value, short offset) {
    if (Util.arrayCompare(scope, (short) 0, value, offset, (short) scope.length) != 0) {
      clear();
      Util.arrayCopyNonAtomic(value, offset, scope, (short) 0, (short) scope.length);
    }
  }

  private void writeLookupKey(byte[] rpHash) {
    Util.arrayCopyNonAtomic(scope, (short) 0, lookupKey, (short) 0, (short) 32);
    Util.arrayCopyNonAtomic(rpHash, (short) 0, lookupKey, (short) 32, (short) 32);
  }

  void clear() {
    for (short slot = 0; slot < DISCOVERY_CAPACITY; slot++) {
      if (sources[slot] != null) {
        sources[slot] = null;
      }
    }
  }

  private Credential readCached(Monoid monoid, byte[] index, short offset, byte[] key) {
    for (short slot = 0; slot < DISCOVERY_CAPACITY; slot++) {
      if (sources[slot] == null) {
        continue;
      }
      Credential credential = cached[slot];
      credential.restoreState();
      if (credential.matchesIndex(index, offset) && credential.matchesKey(key)) {
        // Validate through the current authenticated session, including after a card reset.
        if (monoid.isDataCurrent(sources[slot])) {
          return credential;
        }
        sources[slot] = null;
        break;
      }
    }
    byte[] window = APDU.getCurrentAPDUBuffer();
    Util.arrayCopyNonAtomic(index, offset, window, (short) 0, (short) 10);
    Util.arrayCopyNonAtomic(key, (short) 0, window, (short) 10, (short) key.length);
    SafeDataShareable source = monoid.getData(
      window,
      (short) 0,
      window,
      (short) 10,
      (short) key.length
    );
    if (source == null) {
      return null;
    }
    short length = source.getLength();
    if (length > Credential.READ_BUFFER_LENGTH) {
      Credential credential = remember(Credential.read(source, length, workspace(length)));
      credential.assertMetadata(index, offset, key);
      return credential;
    }
    short slot = nextCache;
    // Invalidate before overwriting persistent bytes; a power cut cannot publish a partial view.
    if (sources[slot] != null) {
      sources[slot] = null;
    }
    Credential credential = cached[slot];
    Credential.read(source, length, credential);
    credential.assertMetadata(index, offset, key);
    credential.saveState(window);
    sources[slot] = source;
    // Publish one valid cursor value, including if power is lost at the wrap boundary.
    nextCache = slot == (short) (DISCOVERY_CAPACITY - 1) ? 0 : (short) (slot + 1);
    return credential;
  }

  void save(Monoid monoid, Credential credential) {
    clear();
    SafeItemShareable[] previous = credential.resident() ? findPrevious(monoid, credential) : null;
    if (previous != null) {
      // Reclaim interrupted replacements before allocating another record, keeping one usable key.
      for (short index = 1; index < previous.length && previous[index] != null; index++) {
        previous[index].remove();
        previous[index] = null;
      }
    }
    // Save first so a failed creation cannot discard an existing credential.
    credential.create(monoid, APDU.getCurrentAPDUBuffer());
    if (previous != null && previous.length != 0 && previous[0] != null) {
      previous[0].remove();
    }
    clear();
  }

  private SafeItemShareable[] findPrevious(Monoid monoid, Credential replacement) {
    byte[] key = replacement.key();
    byte[] window = APDU.getCurrentAPDUBuffer();
    short size = monoid.listIndices(
      CREDENTIAL_TYPE,
      key,
      (short) 0,
      (short) key.length,
      window,
      (short) 0,
      DISCOVERY_CAPACITY
    );
    if (size > DISCOVERY_CAPACITY) {
      return findPreviousAll(monoid, replacement, key);
    }
    Util.arrayCopyNonAtomic(window, (short) 0, indices, (short) 0, (short) (size * 10));
    SafeItemShareable[] previous = null;
    byte[] itemIndex = null;
    short count = 0;
    for (short index = 0; index < size; index++) {
      short offset = (short) (index * 10);
      Credential credential = readIndex(monoid, offset, key, window);
      if (
        credential.resident() && credential.sameUser(replacement) && !credential.sameId(replacement)
      ) {
        if (previous == null) {
          previous = new SafeItemShareable[size];
          itemIndex = Utils.makeGlobalByteArray((short) 10);
        }
        Util.arrayCopyNonAtomic(indices, offset, itemIndex, (short) 0, (short) 10);
        previous[count++] = monoid.get(itemIndex);
      }
    }
    return previous;
  }

  private SafeItemShareable[] findPreviousAll(Monoid monoid, Credential replacement, byte[] key) {
    SafeItemIteratorShareable iterator = monoid.list(CREDENTIAL_TYPE, key);
    short size = iterator.getCount();
    if (size == 0) {
      return null;
    }
    SafeItemShareable[] previous = null;
    short count = 0;
    SafeItemShareable item;
    while ((item = iterator.next()) != null) {
      Credential credential = read(item);
      if (
        credential.resident() && credential.sameUser(replacement) && !credential.sameId(replacement)
      ) {
        if (previous == null) {
          previous = new SafeItemShareable[size];
        }
        previous[count++] = item;
      }
    }
    return previous;
  }

  Selection discover(Monoid monoid, byte[] rpHash) {
    selection.set((short) 0, null);
    writeLookupKey(rpHash);

    byte[] window = APDU.getCurrentAPDUBuffer();
    Util.arrayCopyNonAtomic(lookupKey, (short) 0, window, (short) 0, (short) lookupKey.length);
    short size = monoid.listIndices(
      CREDENTIAL_TYPE,
      window,
      (short) 0,
      (short) lookupKey.length,
      window,
      (short) lookupKey.length,
      DISCOVERY_CAPACITY
    );
    if (size > DISCOVERY_CAPACITY) {
      return discoverAll(monoid, rpHash);
    }
    Util.arrayCopyNonAtomic(
      window,
      (short) lookupKey.length,
      indices,
      (short) 0,
      (short) (size * 10)
    );
    short count = 0;
    Credential first = null;
    for (short index = 0; index < size; index++) {
      Credential credential = readCached(monoid, indices, (short) (index * 10), lookupKey);
      if (credential == null) {
        ISOException.throwIt(CTAP.OTHER);
      }
      if (credential.resident() && credential.matchesKey(lookupKey)) {
        credential.copyId(selection.ids, (short) (count++ * 32));
        first = credential;
      } else {
        first = null;
      }
    }
    if (first == null && count != 0) {
      first = find(monoid, selection.ids, (short) ((count - 1) * 32), rpHash);
    }
    selection.set(count, first);
    return selection;
  }

  private Credential readIndex(Monoid monoid, short offset, byte[] key, byte[] window) {
    Util.arrayCopyNonAtomic(indices, offset, window, (short) 0, (short) 10);
    Util.arrayCopyNonAtomic(key, (short) 0, window, (short) 10, (short) key.length);
    short length = monoid.readData(
      window,
      (short) 0,
      window,
      (short) 10,
      (short) key.length,
      window,
      (short) 0,
      (short) window.length
    );
    // Enumeration already matched this prefix. A missing record or an inexact metadata key
    // cannot silently disappear from the result; the iterator path fails on these too.
    if (length < 0) {
      ISOException.throwIt(CTAP.OTHER);
    }
    Credential credential;
    if (length <= window.length) {
      credential = read(window, length);
    } else {
      byte[] index = Utils.makeGlobalByteArray((short) 10);
      Util.arrayCopyNonAtomic(indices, offset, index, (short) 0, (short) 10);
      credential = read(monoid.get(index));
    }
    credential.assertMetadata(indices, offset, key);
    return credential;
  }

  private Selection discoverAll(Monoid monoid, byte[] rpHash) {
    byte[] key = Utils.duplicateAsGlobal(lookupKey);
    SafeItemIteratorShareable iterator = monoid.list(CREDENTIAL_TYPE, key);
    byte[] ids = new byte[(short) (iterator.getCount() * 32)];
    short count = 0;
    Credential first = null;
    byte[] index = Utils.makeGlobalByteArray((short) 10);
    byte[] window = APDU.getCurrentAPDUBuffer();
    short length;
    while (
      (length = iterator.nextData(
          key,
          index,
          (short) 0,
          window,
          (short) 0,
          (short) window.length
        )) >=
      0
    ) {
      Credential credential = length <= window.length
        ? read(window, length)
        : read(monoid.get(index));
      credential.assertMetadata(index, (short) 0, key);
      if (credential.resident() && credential.matchesKey(key)) {
        credential.copyId(ids, (short) (count++ * 32));
        first = credential;
      } else {
        // The workspace was overwritten, but the last matching ID remains in the selection.
        first = null;
      }
    }
    if (first == null && count != 0) {
      first = find(monoid, ids, (short) ((count - 1) * 32), rpHash);
    }
    Selection result = new Selection(ids);
    result.set(count, first);
    return result;
  }

  private Credential read(SafeItemShareable item) {
    SafeDataShareable source = item.getData();
    short length = source.getLength();
    return remember(Credential.read(item, source, length, workspace(length)));
  }

  private Credential read(byte[] window, short length) {
    return remember(Credential.read(window, (short) 0, length, workspace(length)));
  }

  private Credential workspace(short length) {
    return length <= Credential.READ_BUFFER_LENGTH ? workspace : largeWorkspace;
  }

  private Credential remember(Credential credential) {
    if (credential.getLength() <= Credential.READ_BUFFER_LENGTH) {
      if (credential != workspace) {
        workspace = credential;
      }
    } else if (credential != largeWorkspace) {
      largeWorkspace = credential;
    }
    return credential;
  }

  /** Only IDs survive between assertions; first borrows this operation's decoded workspace. */
  static final class Selection {

    final byte[] ids;
    private final short[] count = JCSystem.makeTransientShortArray(
      (short) 1,
      JCSystem.CLEAR_ON_DESELECT
    );
    private final Object[] first = JCSystem.makeTransientObjectArray(
      (short) 1,
      JCSystem.CLEAR_ON_DESELECT
    );

    Selection(byte[] ids) {
      this.ids = ids;
    }

    void set(short count, Credential first) {
      this.count[0] = count;
      this.first[0] = first;
    }

    short count() {
      return count[0];
    }

    Credential takeFirst() {
      Credential credential = (Credential) first[0];
      first[0] = null;
      return credential;
    }

    short offset(short position) {
      return (short) ((count[0] - position - 1) * 32);
    }
  }
}
