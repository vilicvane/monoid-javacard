package monoid;

public interface CBORResponse {
  /** Writes one complete unit and returns whether further units remain. */
  boolean writeNext(CBORWriter writer) throws MonoidException;

  /** Releases the response state after completion or cancellation. */
  void reset();
}
