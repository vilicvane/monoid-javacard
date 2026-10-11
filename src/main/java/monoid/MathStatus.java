// Derived from JCEd25519 / JCMathLib 2.1-rc.1 (MIT).
// Copyright (c) 2022 Antonin Dufka; JCMathLib authors Vasilios Mavroudis, Petr Svenda, Antonin Dufka.
// Source, changes and licenses: third-party/jced25519/PROVENANCE.md.
package monoid;

public final class MathStatus {

  // Custom error response codes
  public static final short SW_BIG_NAT_INVALID_SIZE = (short) 0x7000;
  public static final short SW_BIG_NAT_REALLOCATION_NOT_ALLOWED = (short) 0x7001;
  public static final short SW_BIG_NAT_MODULUS_TOO_LARGE = (short) 0x7002;
  public static final short SW_BIG_NAT_INVALID_COPY = (short) 0x7003;
  public static final short SW_BIG_NAT_INVALID_RESIZE = (short) 0x7004;
  public static final short SW_BIG_NAT_INVALID_MULTIPLICATION = (short) 0x7005;
  public static final short SW_BIG_NAT_INVALID_SQUARE = (short) 0x7006;
  public static final short SW_EC_POINT_INVALID_LENGTH = (short) 0x7020;
  public static final short SW_EC_POINT_UNEXPECTED_AGREEMENT_LENGTH = (short) 0x7021;
  public static final short SW_EC_POINT_INVALID = (short) 0x7022;
  public static final short SW_ALLOCATOR_INVALID_ID = (short) 0x7030;
  public static final short SW_OPERATION_NOT_SUPPORTED = (short) 0x7040;
}
