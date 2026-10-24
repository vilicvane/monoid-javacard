package tests;

import static tests.MonoidClientFixture.*;
import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.fields;

import java.lang.reflect.Field;
import monoid.Monoid;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class MonoidUserAuthenticationTest {

  @Test
  public void accessAndSecretApprovalSurviveSelectAndAreConsumedAcrossAllSessions() {
    for (boolean secret : new boolean[] { false, true }) {
      try (MonoidClientFixture fixture = new MonoidClientFixture()) {
        fixture.grant(CLIENT);
        fixture.approve(CLIENT, secret);
        Monoid first = fixture.connect();
        Monoid second = fixture.connect(CLIENT, (byte) 1, true);
        first.consumeUserAuthentication();
        assertStatus(0x6982, second::consumeUserAuthentication);
        first.revokeUserAuthentication();
        second.revokeUserAuthentication();
        Assertions.assertEquals(0, first.list((short) 0).getCount());
        Monoid reacquired = fixture.connect(CLIENT, (byte) 1, true);
        assertStatus(0x6982, reacquired::consumeUserAuthentication);
      }
    }
  }

  @Test
  public void callerTokenAndGrantChecksPrecedeConsumptionOrRevocation() {
    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      fixture.grant(CLIENT);
      fixture.grant(OTHER);
      fixture.approve(CLIENT);
      Monoid owner = fixture.connect(CLIENT, (byte) 0, false);
      assertStatus(0x6982, owner::consumeUserAuthentication);
      assertStatus(0x6982, owner::revokeUserAuthentication);
      owner.authenticate(global(fixture.client.token));
      Monoid other = fixture.connect(OTHER, (byte) 0, true);
      assertStatus(0x6982, owner::consumeUserAuthentication);
      assertStatus(0x6982, owner::revokeUserAuthentication);
      assertStatus(0x6982, other::consumeUserAuthentication);
      other.revokeUserAuthentication();
      fixture.select(CLIENT);
      owner.consumeUserAuthentication();
      Assertions.assertEquals(0, owner.list((short) 0).getCount());
    }
  }

  @Test
  public void aNewAuthenticationAlwaysClearsThePreviousPendingApproval() {
    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      fixture.grant(CLIENT);
      fixture.grant(OTHER);
      fixture.approve(CLIENT);
      fixture.card.authenticate(false);
      assertStatus(0x6982, fixture.connect()::consumeUserAuthentication);

      fixture.approve(CLIENT);
      assertError(fixture.card.transmit(0x21, fields("pin", "000000")), "INVALID_PIN");
      // Existing APDU authorization is deliberately preserved after an incorrect PIN.
      fixture.card.success(0x50, fields());
      assertStatus(0x6982, fixture.connect()::consumeUserAuthentication);

      fixture.approve(CLIENT);
      assertError(
        fixture.card.transmit(0x21, fields("pin", "123456", "aid", new byte[4])),
        "INVALID_PARAMETER"
      );
      assertStatus(0x6982, fixture.connect()::consumeUserAuthentication);

      fixture.approve(CLIENT);
      assertError(
        fixture.card.transmit(0x21, fields("pin", "123456", "aid", new byte[7])),
        "NOT_FOUND"
      );
      assertStatus(0x6982, fixture.connect()::consumeUserAuthentication);

      fixture.approve(CLIENT);
      fixture.approve(OTHER);
      assertStatus(0x6982, fixture.connect()::consumeUserAuthentication);
      fixture.connect(OTHER, (byte) 0, true).consumeUserAuthentication();
    }
  }

  @Test
  public void onlyTheMatchingGrantReplacementOrRemovalClearsApproval() {
    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      fixture.grant(CLIENT);
      fixture.grant(OTHER);
      fixture.approve(CLIENT);
      fixture.grant(OTHER);
      fixture.connect().consumeUserAuthentication();

      fixture.approve(CLIENT);
      fixture.grant(CLIENT);
      assertStatus(0x6982, fixture.connect()::consumeUserAuthentication);

      fixture.approve(CLIENT);
      fixture.card.success(0x52, fields("aid", AppletTest.aidBytes(OTHER)));
      fixture.connect().consumeUserAuthentication();

      fixture.approve(CLIENT);
      fixture.card.success(0x52, fields("aid", AppletTest.aidBytes(CLIENT)));
      fixture.grant(CLIENT);
      assertStatus(0x6982, fixture.connect()::consumeUserAuthentication);
    }
  }

  @Test
  public void replacedSessionsCannotConsumeOrRevokeANewGrantApproval() {
    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      fixture.grant(CLIENT);
      Monoid old = fixture.connect();
      fixture.approve(CLIENT);
      fixture.grant(CLIENT);
      fixture.approve(CLIENT);
      Monoid current = fixture.connect();
      assertStatus(0x6982, old::consumeUserAuthentication);
      assertStatus(0x6982, old::revokeUserAuthentication);
      current.consumeUserAuthentication();
    }
  }

  @Test
  public void resetAndEitherPINUpdateRevokeApproval() {
    for (int operation = 0; operation < 4; operation++) {
      try (MonoidClientFixture fixture = new MonoidClientFixture()) {
        fixture.grant(CLIENT);
        fixture.approve(CLIENT, true);
        if (operation == 0) {
          fixture.card.reset();
        } else if (operation == 1 || operation == 2) {
          fixture.card.success(
            0x22,
            operation == 2 ? fields("pin", "987654", "secret", true) : fields("pin", "987654")
          );
        } else {
          fixture.card.success(0xFF, fields());
          fixture.card.success(0x22, fields("pin", "888888", "secret", true));
          fixture.card.authenticate(true);
          fixture.grant(CLIENT);
        }
        assertStatus(0x6982, fixture.connect()::consumeUserAuthentication);
      }
    }
  }

  @Test
  public void damagedEncodedApprovalFailsClosed() throws Exception {
    try (MonoidClientFixture fixture = new MonoidClientFixture()) {
      fixture.grant(CLIENT);
      for (int part = 0; part < 2; part++) {
        for (int bit = 0; bit < 16; bit++) {
          fixture.approve(CLIENT);
          Monoid session = fixture.connect();
          Object implementation = unwrap(session);
          Object safe = field(implementation, "safe");
          Object grants = field(safe, "appletGrants");
          short[] auth = (short[]) field(grants, "userAuth");
          auth[part] ^= (short) (1 << bit);
          assertStatus(0x6982, session::consumeUserAuthentication);
          session.revokeUserAuthentication();
        }
      }
    }
  }

  private static Object unwrap(Object value) throws Exception {
    if (java.lang.reflect.Proxy.isProxyClass(value.getClass())) {
      Object handler = java.lang.reflect.Proxy.getInvocationHandler(value);
      for (Field captured : handler.getClass().getDeclaredFields()) {
        captured.setAccessible(true);
        Object target = captured.get(handler);
        if (target instanceof javacard.framework.Shareable) {
          return target;
        }
      }
    }
    return value;
  }

  private static Object field(Object value, String name) throws Exception {
    Field field = value.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(value);
  }
}
