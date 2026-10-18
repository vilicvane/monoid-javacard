package monoid;

import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import monoidsafe.SafeItemIteratorShareable;
import monoidsafe.SafeItemShareable;
import monoidsafe.SafeShareable;

public class CommandList extends Command implements CBORResponse {

  private final Object[] references = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final short[] state = JCSystem.makeTransientShortArray(
    (short) 2,
    JCSystem.CLEAR_ON_DESELECT
  );

  @Override
  protected void run() throws MonoidException {
    requireAuth();

    MonoidApplet.checkSafeUnlocked();

    reader.map();

    short type = reader.key(Text.type)
      ? reader.is(CBOR.TYPE_TEXT) ? Safe.type(reader) : reader.integer()
      : 0;

    byte[] keyPrefix = reader.key(Text.keyPrefix) ? reader.bytes() : null;

    SafeItemIteratorShareable items = MonoidApplet.safe.list(type, keyPrefix);
    short count = items.getCount();

    references[0] = items;
    state[0] = count;
    state[1] = items.getMaxMetadataLength();

    writer.start(this, maxEncodedItemLength(state[1]));

    writer.map((short) 1);
    {
      writer.text(Text.items);
      writer.array(count);
    }
  }

  private short maxEncodedItemLength(short metadataLength) {
    // One map, five field names, three metadata lengths (up to three bytes each),
    // the longest type name and one boolean. Metadata itself is copied unchanged.
    return (short) (metadataLength +
      17 +
      Text.type.length +
      Text.key.length +
      Text.alias.length +
      Text.index.length +
      Text.secret.length +
      Safe.TYPE_TEXT_SECP256K1.length);
  }

  @Override
  public boolean writeNext(CBORWriter writer) throws MonoidException {
    if (state[0] == 0) {
      return false;
    }

    SafeItemShareable item = ((SafeItemIteratorShareable) references[0]).next();
    byte[] metadata = APDU.getCurrentAPDUBuffer();

    if (state[1] > metadata.length) {
      metadata = Utils.makeGlobalByteArray(state[1]);
    }

    short indexLength = item.getIndex(metadata, (short) 0);
    byte[] typeName = Safe.type(Util.getShort(metadata, SafeShareable.INDEX_TYPE_OFFSET));
    short keyOffset = indexLength;
    short keyLength = item.getKey(metadata, keyOffset);
    short aliasOffset = (short) (keyOffset + (keyLength > 0 ? keyLength : 0));
    short aliasLength = item.getAlias(metadata, aliasOffset);

    short entries = 2;

    if (typeName != null) {
      entries++;
    }

    if (keyLength >= 0) {
      entries++;
    }

    if (aliasLength >= 0) {
      entries++;
    }

    writer.map(entries);
    {
      if (typeName != null) {
        writer.text(Text.type);
        writer.text(typeName);
      }

      if (keyLength >= 0) {
        writer.text(Text.key);
        writer.bytes(metadata, keyOffset, keyLength);
      }

      if (aliasLength >= 0) {
        writer.text(Text.alias);
        writer.text(metadata, aliasOffset, aliasLength);
      }

      writer.text(Text.index);
      writer.bytes(metadata, (short) 0, indexLength);

      writer.text(Text.secret);
      writer.bool(item.isSecret());
    }

    return --state[0] > 0;
  }

  @Override
  public void reset() {
    references[0] = null;
    state[0] = 0;
    state[1] = 0;
  }
}
