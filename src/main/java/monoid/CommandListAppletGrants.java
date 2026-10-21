package monoid;

import javacard.framework.JCSystem;

public final class CommandListAppletGrants extends Command implements CBORResponse {

  private final Object[] references = JCSystem.makeTransientObjectArray(
    (short) 1,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final short[] state = JCSystem.makeTransientShortArray(
    (short) 1,
    JCSystem.CLEAR_ON_DESELECT
  );

  @Override
  protected void run() {
    AppletGrant[] grants = MonoidApplet.safe.getAppletGrants().list();
    reader.map();

    short count = grants == null ? 0 : (short) grants.length;
    short maxLength = 0;

    for (short index = 0; index < count; index++) {
      short length = grants[index].getMaxEncodedLength();

      if (length > maxLength) {
        maxLength = length;
      }
    }

    writer.start(this, maxLength);
    references[0] = grants;
    state[0] = 0;
    writer.map((short) 1);
    writer.text(Text.grants);
    writer.array(count);
  }

  @Override
  public boolean writeNext(CBORWriter writer) {
    AppletGrant[] grants = (AppletGrant[]) references[0];

    if (grants == null || state[0] >= grants.length) {
      return false;
    }

    grants[state[0]++].write(writer);
    return state[0] < grants.length;
  }

  @Override
  public void reset() {
    references[0] = null;
    state[0] = 0;
  }
}
