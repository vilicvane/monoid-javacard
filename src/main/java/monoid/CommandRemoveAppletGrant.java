package monoid;

public final class CommandRemoveAppletGrant extends Command {

  @Override
  protected void run() {
    AppletGrants grants = MonoidApplet.safe.getAppletGrants();
    grants.assertManagement();

    reader.map();
    byte[] aid = reader.requireKey(Text.aid).bytes();

    if (aid.length < 5 || aid.length > 16) {
      MonoidException.throwIt(MonoidException.CODE_INVALID_PARAMETER);
    }

    grants.remove(aid);
    writeEmptyMap();
  }
}
