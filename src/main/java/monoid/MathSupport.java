// Derived from JCEd25519 / JCMathLib 2.1-rc.1 (MIT).
// Copyright (c) 2022 Antonin Dufka; JCMathLib authors Vasilios Mavroudis, Petr Svenda, Antonin Dufka.
// Source, changes and licenses: third-party/jced25519/PROVENANCE.md.
package monoid;

public final class MathSupport {

  private static MathSupport instance;

  public static final short SIMULATOR = 0x0000; // jCardSim.org simulator
  public static final short JCOP21 = 0x0001; // NXP J2E145G
  public static final short JCOP3_P60 = 0x0002; // NXP JCOP3 J3H145 P60
  public static final short JCOP4_P71 = 0x0003; // NXP JCOP4 J3Rxxx P71
  public static final short GD60 = 0x0004; // G+D Sm@rtcafe 6.0
  public static final short GD70 = 0x0005; // G+D Sm@rtcafe 7.0
  public static final short SECORA = 0x0006; // Infineon Secora ID S

  public short minRSABitLength = 512;

  public boolean rsaExponentiation = true;
  public boolean rsaSquaring = true;
  public boolean rsaPublicKey = false;
  public boolean rsaCheckOne = false;
  public boolean rsaCheckExponentOne = false;
  public boolean rsaKeyRefresh = false;
  public boolean rsaPrependZeros = false;
  public boolean rsaExtraModulo = false;
  public boolean rsaResizeModulus = true;
  public boolean rsaAppendModulus = false;

  public boolean ecHardwareXY = false;
  public boolean ecHardwareX = true;
  public boolean ecHardwareAddition = false;
  public boolean ecSoftwareDouble = false;
  public boolean ecPreciseBitLength = true;
  public boolean ecSetCofactor = false;
  public boolean ecKeyGeneration = true;
  public boolean ecHardwareXECDSA = true;

  private MathSupport() {}

  public static MathSupport getInstance() {
    if (MathSupport.instance == null) {
      MathSupport.instance = new MathSupport();
    }

    return MathSupport.instance;
  }

  public void setCard(short cardType) {
    switch (cardType) {
      case SIMULATOR:
        rsaKeyRefresh = true;
        rsaPrependZeros = true;
        rsaResizeModulus = false;
        ecHardwareXY = true;
        ecHardwareAddition = true;
        ecSoftwareDouble = true;
        ecPreciseBitLength = false;
        break;
      case JCOP21:
        rsaPublicKey = true;
        rsaExtraModulo = true;
        rsaAppendModulus = true;
        ecSoftwareDouble = true;
        ecKeyGeneration = false; // required by CurveWEI25519
        ecHardwareXECDSA = false; // required by CurveWEI25519
        break;
      case GD60:
        rsaPublicKey = true;
        rsaExtraModulo = true;
        rsaAppendModulus = true;
        break;
      case GD70:
        rsaPublicKey = true;
        rsaCheckOne = true;
        rsaExtraModulo = true;
        rsaAppendModulus = true;
        break;
      case JCOP3_P60:
        rsaPublicKey = true;
        ecHardwareXY = true;
        ecHardwareAddition = true;
        break;
      case JCOP4_P71:
        ecHardwareXY = true;
        ecHardwareAddition = true;
        break;
      case SECORA:
        minRSABitLength = 1024;
        rsaSquaring = false;
        rsaCheckExponentOne = true;
        rsaPublicKey = true;
        rsaExtraModulo = true;
        rsaAppendModulus = true;
        ecHardwareXY = true;
        ecPreciseBitLength = false;
        break;
      default:
        break;
    }
  }
}
