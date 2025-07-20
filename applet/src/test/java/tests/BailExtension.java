package tests;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.TestWatcher;
import org.opentest4j.TestAbortedException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * JUnit 5 extension that implements "fail-fast" behavior.
 * When one test fails, all subsequent tests in the same class are skipped.
 *
 * Usage:
 * @ExtendWith(BailExtension.class)
 * class MyTestClass {
 *     // tests here
 * }
 */
public class BailExtension implements TestWatcher, BeforeEachCallback {

  // Static map to track failed test classes across the entire test run
  private static final Map<String, Boolean> failedClasses = new ConcurrentHashMap<>();

  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    String testClassName = getTestClassName(context);

    if (Boolean.TRUE.equals(failedClasses.get(testClassName))) {
      throw new TestAbortedException("Skipping test because a previous test in this class failed");
    }
  }

  @Override
  public void testFailed(ExtensionContext context, Throwable cause) {
    String testClassName = getTestClassName(context);
    failedClasses.put(testClassName, true);
  }

  private String getTestClassName(ExtensionContext context) {
    return context.getRequiredTestClass().getName();
  }

  /**
   * Optional: Clear the failure state for a specific class
   * Useful for programmatic reset during test development
   */
  public static void clearFailureState(Class<?> testClass) {
    failedClasses.remove(testClass.getName());
  }

  /**
   * Optional: Clear all failure states
   * Useful for programmatic reset during test development
   */
  public static void clearAllFailureStates() {
    failedClasses.clear();
  }
}
