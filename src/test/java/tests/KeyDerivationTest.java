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
  public void clearingTheCacheDropsAllSeedsAndDerivedResultsAndAllowsReuse() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] seed = new byte[64];

    for (int i = 0; i < 32; i++) {
      derivation.deriveFromSeed(seed, new byte[] { (byte) i });
    }

    KeyDerivation.clearCache();

    for (int i = 0; i < 32; i++) {
      derivation.deriveFromSeed(seed, new byte[] { (byte) i });
    }

    Assertions.assertEquals(64, derivation.calls);
    Assertions.assertEquals(64, derivation.masterCalls);

    for (int i = 0; i < 32; i++) {
      derivation.deriveFromSeed(seed, new byte[] { (byte) i });
    }

    Assertions.assertEquals(64, derivation.calls);
    Assertions.assertEquals(64, derivation.masterCalls);
  }

  @Test
  public void matchingBytesReuseTheResultAsIndependentTransientCopies() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];
    byte[] input = { 1, 2 };
    byte[] first = derivation.derive(master, input).getKey();
    byte[] second = derivation.derive(master.clone(), input.clone()).getKey();
    byte[] third = derivation.derive(master.clone(), input.clone()).getKey();

    Assertions.assertEquals(1, derivation.calls);
    Assertions.assertNotSame(derivation.result, first);
    Assertions.assertArrayEquals(first, second);
    Assertions.assertArrayEquals(first, third);
    Assertions.assertNotSame(first, second);
    Assertions.assertNotSame(second, third);
    Assertions.assertEquals(JCSystem.CLEAR_ON_RESET, JCSystem.isTransient(first));
    Assertions.assertEquals(JCSystem.CLEAR_ON_RESET, JCSystem.isTransient(second));
    Assertions.assertEquals(JCSystem.CLEAR_ON_RESET, JCSystem.isTransient(third));
  }

  @Test
  public void snapshotsTheMasterAndInputBeforeTheirCallersReuseThem() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];
    byte[] input = { 1, 2 };
    byte[] originalMaster = master.clone();
    byte[] originalInput = input.clone();
    byte[] expected = derivation.derive(master, input).getKey().clone();

    master[63] = 1;
    input[1] = 3;

    Assertions.assertArrayEquals(
      expected,
      derivation.derive(originalMaster, originalInput).getKey()
    );
    Assertions.assertEquals(1, derivation.calls);
    derivation.derive(master, input);
    Assertions.assertEquals(2, derivation.calls);
  }

  @Test
  public void mutationsToMissAndHitResultsDoNotChangeTheCachedResult() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];
    byte[] input = new byte[0];
    byte[] first = derivation.derive(master, input).getKey();
    byte[] expected = first.clone();
    first[0] ^= (byte) 0xFF;

    byte[] second = derivation.derive(master, input).getKey();
    Assertions.assertArrayEquals(expected, second);
    second[1] ^= (byte) 0xFF;

    Assertions.assertArrayEquals(expected, derivation.derive(master, input).getKey());
    Assertions.assertEquals(1, derivation.calls);
  }

  @Test
  public void seedPathHitsSkipBothMasterAndPathDerivation() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] seed = new byte[64];
    byte[] input = { 1, 2 };
    byte[] first = derivation.deriveFromSeed(seed, input).getKey();
    byte[] repeated = derivation.deriveFromSeed(seed.clone(), input.clone()).getKey();

    Assertions.assertArrayEquals(first, repeated);
    Assertions.assertNotSame(first, repeated);
    Assertions.assertEquals(1, derivation.masterCalls);
    Assertions.assertEquals(1, derivation.calls);

    first[0] ^= (byte) 0xFF;
    repeated[1] ^= (byte) 0xFF;
    Assertions.assertArrayEquals(
      derivation.result,
      derivation.deriveFromSeed(seed, input).getKey()
    );
    Assertions.assertEquals(1, derivation.masterCalls);
    Assertions.assertEquals(1, derivation.calls);
  }

  @Test
  public void seedAndMasterSourcesRemainDistinctForIdenticalBytes() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] source = new byte[64];
    byte[] input = { 1 };
    byte[] fromSeed = derivation.deriveFromSeed(source, input).getKey();
    byte[] fromMaster = derivation.derive(source, input).getKey();

    Assertions.assertEquals(1, derivation.masterCalls);
    Assertions.assertEquals(2, derivation.calls);
    Assertions.assertArrayEquals(fromSeed, derivation.deriveFromSeed(source, input).getKey());
    Assertions.assertArrayEquals(fromMaster, derivation.derive(source, input).getKey());
    Assertions.assertEquals(1, derivation.masterCalls);
    Assertions.assertEquals(2, derivation.calls);
  }

  @Test
  public void changedSeedAndPathMissWithoutChangingEarlierEntries() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] seed = new byte[64];
    byte[] path = { 1, 2 };
    byte[] originalSeed = seed.clone();
    byte[] originalPath = path.clone();
    byte[] first = derivation.deriveFromSeed(seed, path).getKey();

    seed[63] = 1;
    derivation.deriveFromSeed(seed, path);
    path[1] = 3;
    derivation.deriveFromSeed(seed, path);

    Assertions.assertEquals(3, derivation.masterCalls);
    Assertions.assertEquals(3, derivation.calls);
    Assertions.assertArrayEquals(
      first,
      derivation.deriveFromSeed(originalSeed, originalPath).getKey()
    );
    Assertions.assertEquals(3, derivation.masterCalls);
    Assertions.assertEquals(3, derivation.calls);
  }

  @Test
  public void seedAndMasterPathsShareThirtyTwoCompleteResultSlots() {
    CountingDerivation[] derivations = {
      new CountingDerivation(),
      new CountingDerivation(),
      new CountingDerivation(),
    };
    byte[] source = new byte[64];
    byte[][] expected = new byte[32][];

    for (int i = 0; i < expected.length; i++) {
      CountingDerivation derivation = derivations[i % derivations.length];
      byte[] input = { (byte) i };
      expected[i] = (i % 2 == 0
          ? derivation.deriveFromSeed(source, input)
          : derivation.derive(source, input)).getKey();
    }

    for (int i = 0; i < expected.length; i++) {
      CountingDerivation derivation = derivations[i % derivations.length];
      byte[] input = { (byte) i };
      Assertions.assertArrayEquals(
        expected[i],
        (i % 2 == 0
            ? derivation.deriveFromSeed(source, input)
            : derivation.derive(source, input)).getKey()
      );
    }

    Assertions.assertEquals(32, totalCalls(derivations));
    Assertions.assertEquals(16, totalMasterCalls(derivations));
    derivations[2].deriveFromSeed(source, new byte[] { 32 });
    Assertions.assertEquals(33, totalCalls(derivations));
    Assertions.assertEquals(17, totalMasterCalls(derivations));
    Assertions.assertArrayEquals(
      expected[1],
      derivations[1].derive(source, new byte[] { 1 }).getKey()
    );
    derivations[0].deriveFromSeed(source, new byte[] { 0 });
    Assertions.assertEquals(34, totalCalls(derivations));
    Assertions.assertEquals(18, totalMasterCalls(derivations));
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
      expected[i] = derivation.derive(masters[i], inputs[i]).getKey();
      Assertions.assertEquals(i + 1, derivation.calls);
    }

    for (int i = 0; i < masters.length; i++) {
      Assertions.assertArrayEquals(
        expected[i],
        derivation.derive(masters[i].clone(), inputs[i].clone()).getKey()
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
      expected[i] = derivations[i % 3].derive(master, new byte[] { (byte) i }).getKey();
    }

    for (int i = 0; i < 32; i++) {
      Assertions.assertArrayEquals(
        expected[i],
        derivations[i % 3].derive(master, new byte[] { (byte) i }).getKey()
      );
    }

    Assertions.assertEquals(32, totalCalls(derivations));
    expected[32] = derivations[2].derive(master, new byte[] { 32 }).getKey();

    for (int i = 1; i <= 32; i++) {
      Assertions.assertArrayEquals(
        expected[i],
        derivations[i % 3].derive(master, new byte[] { (byte) i }).getKey()
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
      expected[i] = derivation.derive(master, new byte[] { (byte) i }).getKey();
    }

    for (int i = 43; i < 75; i++) {
      Assertions.assertArrayEquals(
        expected[i],
        derivation.derive(master, new byte[] { (byte) i }).getKey()
      );
    }

    Assertions.assertEquals(75, derivation.calls);
    expected[75] = derivation.derive(master, new byte[] { 75 }).getKey();

    for (int i = 44; i <= 75; i++) {
      Assertions.assertArrayEquals(
        expected[i],
        derivation.derive(master, new byte[] { (byte) i }).getKey()
      );
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
    byte[] expected = first.derive(master, input).getKey().clone();
    second.derive(master, input);
    second.derive(master, new byte[] { 2 });

    Assertions.assertArrayEquals(expected, first.derive(master, input).getKey());
    Assertions.assertEquals(1, first.calls);
    Assertions.assertEquals(2, second.calls);
  }

  @Test
  public void failedDerivationLeavesThePreviousEntryUsable() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];
    byte[] input = { 1 };
    byte[] expected = derivation.derive(master, input).getKey().clone();
    derivation.fail = true;

    CryptoException exception = Assertions.assertThrows(CryptoException.class, () ->
      derivation.derive(master, new byte[] { 2 }).getKey()
    );

    Assertions.assertEquals(CryptoException.ILLEGAL_USE, exception.getReason());
    Assertions.assertArrayEquals(expected, derivation.derive(master, input).getKey());
    Assertions.assertEquals(2, derivation.calls);
  }

  @Test
  public void failedDerivationPreservesAFullPoolAndItsInsertionOrder() {
    CountingDerivation derivation = new CountingDerivation();
    byte[] master = new byte[64];
    byte[][] expected = new byte[32][];

    for (int i = 0; i < 32; i++) {
      expected[i] = derivation.derive(master, new byte[] { (byte) i }).getKey();
    }

    derivation.fail = true;
    CryptoException exception = Assertions.assertThrows(CryptoException.class, () ->
      derivation.derive(master, new byte[] { 32 }).getKey()
    );

    Assertions.assertEquals(CryptoException.ILLEGAL_USE, exception.getReason());

    for (int i = 0; i < 32; i++) {
      Assertions.assertArrayEquals(
        expected[i],
        derivation.derive(master, new byte[] { (byte) i }).getKey()
      );
    }

    Assertions.assertEquals(33, derivation.calls);
    derivation.fail = false;
    derivation.derive(master, new byte[] { 32 });

    for (int i = 1; i < 32; i++) {
      Assertions.assertArrayEquals(
        expected[i],
        derivation.derive(master, new byte[] { (byte) i }).getKey()
      );
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
      byte[] expected = derivation.derive(master, input).getKey();
      Assertions.assertArrayEquals(expected, derivation.derive(master, input).getKey());
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

  private static int totalMasterCalls(CountingDerivation[] derivations) {
    int calls = 0;

    for (CountingDerivation derivation : derivations) {
      calls += derivation.masterCalls;
    }

    return calls;
  }

  private static class CountingDerivation extends KeyDerivation {

    private int calls;
    private int masterCalls;
    private boolean fail;
    private byte[] result;

    @Override
    protected byte[] getMasterKeyLabel() {
      return new byte[] { 1 };
    }

    @Override
    protected byte[] deriveMasterFromSeed(byte[] seed) {
      masterCalls++;
      return seed.clone();
    }

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
