package monoidlib;

public interface CBORResponse {
  /** Writes one complete unit and returns whether further units remain. */
  boolean writeNext(CBORWriter writer);

  /** Releases the response state after completion or cancellation. */
  void reset();
}
