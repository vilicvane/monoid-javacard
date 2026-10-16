package tests;

import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import monoid.KeyDerivation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class KeyDerivationTest {

  @BeforeEach
  public void initialize() {
    KeyDerivation.init();
  }

  @AfterEach
  public void dispose() {
    KeyDerivation.dispose();
  }

  @Test
  public void matchingBytesReuseTheResultAsIndependentTransientCopies() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];
    byte[] input = { 1, 2 };
    byte[] first = derivation.derive(master, input);
    byte[] second = derivation.derive(master.clone(), input.clone());
    byte[] third = derivation.derive(master.clone(), input.clone());

    Assertions.assertEquals(1, derivation.calls);
    Assertions.assertSame(derivation.result, first);
    Assertions.assertArrayEquals(first, second);
    Assertions.assertArrayEquals(first, third);
    Assertions.assertNotSame(first, second);
    Assertions.assertNotSame(second, third);
    Assertions.assertEquals(JCSystem.CLEAR_ON_DESELECT, JCSystem.isTransient(second));
    Assertions.assertEquals(JCSystem.CLEAR_ON_DESELECT, JCSystem.isTransient(third));
  }

  @Test
  public void snapshotsTheMasterAndInputBeforeTheirCallersReuseThem() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];
    byte[] input = { 1, 2 };
    byte[] originalMaster = master.clone();
    byte[] originalInput = input.clone();
    byte[] expected = derivation.derive(master, input).clone();

    master[63] = 1;
    input[1] = 3;

    Assertions.assertArrayEquals(expected, derivation.derive(originalMaster, originalInput));
    Assertions.assertEquals(1, derivation.calls);
    derivation.derive(master, input);
    Assertions.assertEquals(2, derivation.calls);
  }

  @Test
  public void mutationsToMissAndHitResultsDoNotChangeTheCachedResult() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];
    byte[] input = new byte[0];
    byte[] first = derivation.derive(master, input);
    byte[] expected = first.clone();
    first[0] ^= (byte) 0xFF;

    byte[] second = derivation.derive(master, input);
    Assertions.assertArrayEquals(expected, second);
    second[1] ^= (byte) 0xFF;

    Assertions.assertArrayEquals(expected, derivation.derive(master, input));
    Assertions.assertEquals(1, derivation.calls);
  }

  @Test
  public void comparesTheWholeMasterAndInputIncludingTheirLengths() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];
    byte[] changedMaster = master.clone();
    changedMaster[63] = 1;
    byte[][] masters = { master, changedMaster, new byte[65], master, master, master };
    byte[][] inputs = {
      new byte[0],
      new byte[0],
      new byte[0],
      new byte[] { 0 },
      new byte[] { 1 },
      new byte[] { 1, 0 },
    };
    byte[][] expected = new byte[masters.length][];

    for (int i = 0; i < masters.length; i++) {
      expected[i] = derivation.derive(masters[i], inputs[i]);
      Assertions.assertEquals(i + 1, derivation.calls);
    }

    for (int i = 0; i < masters.length; i++) {
      Assertions.assertArrayEquals(
        expected[i],
        derivation.derive(masters[i].clone(), inputs[i].clone())
      );
    }

    Assertions.assertEquals(masters.length, derivation.calls);
  }

  @Test
  public void sharesThirtyTwoEntriesAcrossAllDerivationInstances() {
    CountingDerivation[] derivations = {
      new CountingDerivation(),
      new CountingDerivation(),
      new CountingDerivation(),
    };
    byte[] master = new byte[64];
    byte[][] expected = new byte[33][];

    for (int i = 0; i < 32; i++) {
      expected[i] = derivations[i % 3].derive(master, new byte[] { (byte) i });
    }

    for (int i = 0; i < 32; i++) {
      Assertions.assertArrayEquals(
        expected[i],
        derivations[i % 3].derive(master, new byte[] { (byte) i })
      );
    }

    Assertions.assertEquals(32, totalCalls(derivations));
    expected[32] = derivations[2].derive(master, new byte[] { 32 });

    for (int i = 1; i <= 32; i++) {
      Assertions.assertArrayEquals(
        expected[i],
        derivations[i % 3].derive(master, new byte[] { (byte) i })
      );
    }

    Assertions.assertEquals(33, totalCalls(derivations));
    derivations[0].derive(master, new byte[] { 0 });
    Assertions.assertEquals(34, totalCalls(derivations));
  }

  @Test
  public void cacheHitsDoNotRefreshTheInsertionOrder() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];

    for (int i = 0; i < 32; i++) {
      derivation.derive(master, new byte[] { (byte) i });
    }

    derivation.derive(master, new byte[] { 0 });
    Assertions.assertEquals(32, derivation.calls);
    derivation.derive(master, new byte[] { 32 });
    Assertions.assertEquals(33, derivation.calls);
    derivation.derive(master, new byte[] { 0 });
    Assertions.assertEquals(34, derivation.calls);
    derivation.derive(master, new byte[] { 1 });
    Assertions.assertEquals(35, derivation.calls);
  }

  @Test
  public void evictionContinuesAfterWrappingThePoolMoreThanTwice() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];
    byte[][] expected = new byte[76][];

    for (int i = 0; i < 75; i++) {
      expected[i] = derivation.derive(master, new byte[] { (byte) i });
    }

    for (int i = 43; i < 75; i++) {
      Assertions.assertArrayEquals(expected[i], derivation.derive(master, new byte[] { (byte) i }));
    }

    Assertions.assertEquals(75, derivation.calls);
    expected[75] = derivation.derive(master, new byte[] { 75 });

    for (int i = 44; i <= 75; i++) {
      Assertions.assertArrayEquals(expected[i], derivation.derive(master, new byte[] { (byte) i }));
    }

    Assertions.assertEquals(76, derivation.calls);
    derivation.derive(master, new byte[] { 43 });
    Assertions.assertEquals(77, derivation.calls);
  }

  @Test
  public void instancesKeepTheirEntriesDistinctForIdenticalMasterAndInputBytes() {
    CountingDerivation first = new CountingDerivation();
    CountingDerivation second = new CountingDerivation();
    byte[] master = new byte[64];
    byte[] input = { 1 };
    byte[] expected = first.derive(master, input).clone();
    second.derive(master, input);
    second.derive(master, new byte[] { 2 });

    Assertions.assertArrayEquals(expected, first.derive(master, input));
    Assertions.assertEquals(1, first.calls);
    Assertions.assertEquals(2, second.calls);
  }

  @Test
  public void failedDerivationLeavesThePreviousEntryUsable() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];
    byte[] input = { 1 };
    byte[] expected = derivation.derive(master, input).clone();
    derivation.fail = true;

    CryptoException exception = Assertions.assertThrows(CryptoException.class, () ->
      derivation.derive(master, new byte[] { 2 })
    );

    Assertions.assertEquals(CryptoException.ILLEGAL_USE, exception.getReason());
    Assertions.assertArrayEquals(expected, derivation.derive(master, input));
    Assertions.assertEquals(2, derivation.calls);
  }

  @Test
  public void failedDerivationPreservesAFullPoolAndItsInsertionOrder() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];
    byte[][] expected = new byte[32][];

    for (int i = 0; i < 32; i++) {
      expected[i] = derivation.derive(master, new byte[] { (byte) i });
    }

    derivation.fail = true;
    CryptoException exception = Assertions.assertThrows(CryptoException.class, () ->
      derivation.derive(master, new byte[] { 32 })
    );

    Assertions.assertEquals(CryptoException.ILLEGAL_USE, exception.getReason());

    for (int i = 0; i < 32; i++) {
      Assertions.assertArrayEquals(expected[i], derivation.derive(master, new byte[] { (byte) i }));
    }

    Assertions.assertEquals(33, derivation.calls);
    derivation.fail = false;
    derivation.derive(master, new byte[] { 32 });

    for (int i = 1; i < 32; i++) {
      Assertions.assertArrayEquals(expected[i], derivation.derive(master, new byte[] { (byte) i }));
    }

    Assertions.assertEquals(34, derivation.calls);
    derivation.derive(master, new byte[] { 0 });
    Assertions.assertEquals(35, derivation.calls);
  }

  @Test
  public void disposingAndReinitializingThePoolInvalidatesAllEntries() {
    CountingDerivation[] derivations = {
      new CountingDerivation(),
      new CountingDerivation(),
      new CountingDerivation(),
    };
    byte[] master = new byte[64];
    byte[] input = { 1 };

    for (CountingDerivation derivation : derivations) {
      derivation.derive(master, input);
    }

    KeyDerivation.dispose();
    KeyDerivation.init();

    for (CountingDerivation derivation : derivations) {
      byte[] expected = derivation.derive(master, input);
      Assertions.assertArrayEquals(expected, derivation.derive(master, input));
      Assertions.assertEquals(2, derivation.calls);
    }
  }

  private static int totalCalls(CountingDerivation[] derivations) {
    int calls = 0;

    for (CountingDerivation derivation : derivations) {
      calls += derivation.calls;
    }

    return calls;
  }

  private static class CountingDerivation extends KeyDerivation {

    private int calls;
    private boolean fail;
    private byte[] result;

    @Override
    protected byte[] deriveKey(byte[] master, byte[] input) {
      calls++;

      if (fail) {
        CryptoException.throwIt(CryptoException.ILLEGAL_USE);
      }

      result = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
      result[0] = (byte) calls;
      result[1] = (byte) 0x80;

      return result;
    }
  }
}
