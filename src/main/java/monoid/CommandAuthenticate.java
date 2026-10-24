package monoid;

public class CommandAuthenticate extends Command {

  @Override
  protected void run() throws MonoidException {
    AppletGrants grants = MonoidApplet.safe.getAppletGrants();
    grants.clearUserAuthentication();

    reader.snapshot();
    reader.map();
    AppletGrant grant = reader.key(Text.aid) ? grants.require(reader.bytes()) : null;
    reader.restore();

    authenticate();

    if (grant != null) {
      grants.grantUserAuthentication(grant);
    }

    sendEmptyMap();
  }
}
