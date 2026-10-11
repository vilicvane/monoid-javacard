// Derived from JCEd25519 / JCMathLib 2.1-rc.1 (MIT).
// Copyright (c) 2022 Antonin Dufka; JCMathLib authors Vasilios Mavroudis, Petr Svenda, Antonin Dufka.
// Source, changes and licenses: third-party/jced25519/PROVENANCE.md.
package monoid;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.Signature;

public final class ECPoint {

  private static final byte[] ECDSA_TEST_MESSAGE = { 0x01, 0x01, 0x02, 0x03 };

  private final MathResources resources;

  private ECPublicKey point;
  private KeyPair pointKeyPair;
  private final ECCurve curve;

  /**
   * Creates new ECPoint object for provided {@code curve}. Random initial point value is generated.
   *
   * @param curve point's elliptic curve
   */
  public ECPoint(ECCurve curve) {
    this.curve = curve;
    this.resources = curve.resources;
    updatePointObjects();
  }

  /**
   * Returns length of this point in bytes.
   *
   * @return length of this point in bytes
   */
  public short length() {
    return (short) (point.getSize() / 8);
  }

  /**
   * Properly updates all point values in case of a change of an underlying curve.
   * New random point value is generated.
   */
  public final void updatePointObjects() {
    pointKeyPair = curve.newKeyPair(pointKeyPair);
    point = (ECPublicKey) pointKeyPair.getPublic();
  }

  /**
   * Generates new random point value.
   */
  public void randomize() {
    if (MathSupport.getInstance().ecKeyGeneration) {
      pointKeyPair.genKeyPair(); // Fails for some curves on some cards
    } else {
      BigNat tmp = resources.ecBigNatA;

      OneShot.random(resources.bufferA, (short) 0, (short) (curve.keyBitLength / 8 + 16));
      tmp.fromByteArray(resources.bufferA, (short) 0, (short) (curve.keyBitLength / 8 + 16));
      tmp.mod(curve.rValue);
      tmp.shrink();
      point.setW(curve.g, (short) 0, (short) curve.g.length);
      multiplication(tmp);
    }
  }

  /**
   * Copy value of provided point into this. This and other point must have
   * curve with same parameters, only length is checked.
   *
   * @param other point to be copied
   */
  public void copy(ECPoint other) {
    if (length() != other.length()) {
      ISOException.throwIt(MathStatus.SW_EC_POINT_INVALID_LENGTH);
    }

    byte[] pointBuffer = resources.pointBufferA;

    short len = other.getW(pointBuffer, (short) 0);

    setW(pointBuffer, (short) 0, len);
  }

  /**
   * Set this point value (parameter W) from array with value encoded as per ANSI X9.62.
   * The uncompressed form is always supported. If underlying native JavaCard implementation
   * of {@code ECPublicKey} supports compressed points, then this method accepts also compressed points.
   *
   * @param buffer array with serialized point
   * @param offset start offset within input array
   * @param length length of point
   */
  public void setW(byte[] buffer, short offset, short length) {
    point.setW(buffer, offset, length);
  }

  /**
   * Returns current value of this point.
   *
   * @param buffer memory array where to store serailized point value
   * @param offset start offset for output serialized point
   * @return length of serialized point (number of bytes)
   */
  public short getW(byte[] buffer, short offset) {
    return point.getW(buffer, offset);
  }

  /**
   * Returns this point value as ECPublicKey object. No copy of point is made
   * before return, so change of returned object will also change this point value.
   *
   * @return point as ECPublicKey object
   */
  public ECPublicKey asPublicKey() {
    return point;
  }

  /**
   * Returns curve associated with this point. No copy of curve is made
   * before return, so change of returned object will also change curve for
   * this point.
   *
   * @return curve as ECCurve object
   */
  public ECCurve getCurve() {
    return curve;
  }

  /**
   * Returns the X coordinate of this point in uncompressed form.
   *
   * @param buffer output array for X coordinate
   * @param offset start offset within output array
   * @return length of X coordinate (in bytes)
   */
  public short getX(byte[] buffer, short offset) {
    byte[] pointBuffer = resources.pointBufferA;

    point.getW(pointBuffer, (short) 0);
    Util.arrayCopyNonAtomic(pointBuffer, (short) 1, buffer, offset, curve.coordinateSize);

    return curve.coordinateSize;
  }

  /**
   * Returns the Y coordinate of this point in uncompressed form.
   *
   * @param buffer output array for Y coordinate
   * @param offset start offset within output array
   * @return length of Y coordinate (in bytes)
   */
  public short getY(byte[] buffer, short offset) {
    byte[] pointBuffer = resources.pointBufferA;

    point.getW(pointBuffer, (short) 0);
    Util.arrayCopyNonAtomic(
      pointBuffer,
      (short) (1 + curve.coordinateSize),
      buffer,
      offset,
      curve.coordinateSize
    );

    return curve.coordinateSize;
  }

  /**
   * Double this point. Pure implementation without KeyAgreement.
   */
  public void swDouble() {
    byte[] pointBuffer = resources.pointBufferA;
    BigNat pX = resources.ecBigNatB;
    BigNat pY = resources.ecBigNatC;
    BigNat lambda = resources.ecBigNatD;
    BigNat tmp = resources.ecBigNatE;

    getW(pointBuffer, (short) 0);

    pX.fromByteArray(pointBuffer, (short) 1, curve.coordinateSize);

    pY.fromByteArray(pointBuffer, (short) (1 + curve.coordinateSize), curve.coordinateSize);

    lambda.clone(pX);
    lambda.modSq(curve.pValue);
    lambda.modMult(resources.three, curve.pValue);
    lambda.modAdd(curve.aValue, curve.pValue);

    tmp.clone(pY);
    tmp.modAdd(tmp, curve.pValue);
    tmp.modInv(curve.pValue);
    lambda.modMult(tmp, curve.pValue);
    tmp.clone(lambda);
    tmp.modSq(curve.pValue);
    tmp.modSub(pX, curve.pValue);
    tmp.modSub(pX, curve.pValue);
    tmp.prependZeros(curve.coordinateSize, pointBuffer, (short) 1);

    tmp.modSub(pX, curve.pValue);
    tmp.modMult(lambda, curve.pValue);
    tmp.modAdd(pY, curve.pValue);
    tmp.modNegate(curve.pValue);
    tmp.prependZeros(curve.coordinateSize, pointBuffer, (short) (1 + curve.coordinateSize));

    setW(pointBuffer, (short) 0, curve.pointSize);
  }

  /**
   * Doubles the current value of this point.
   */
  public void makeDouble() {
    // doubling via add sometimes causes exception inside KeyAgreement engine
    // this.add(this);
    // Use bit slower, but more robust version via multiplication by 2
    this.multiplication(resources.two);
  }

  /**
   * Adds this (P) and provided (Q) point. Stores a resulting value into this point.
   *
   * @param other point to be added to this.
   */
  public void add(ECPoint other) {
    if (MathSupport.getInstance().ecHardwareAddition) {
      hwAdd(other);
    } else {
      swAdd(other);
    }
  }

  /**
   * Implements adding of two points without ALG_EC_PACE_GM.
   *
   * @param other point to be added to this.
   */
  private void swAdd(ECPoint other) {
    boolean samePoint = this == other || isEqual(other);

    if (samePoint && MathSupport.getInstance().ecHardwareXY) {
      multiplication(resources.two);

      return;
    }

    byte[] pointBuffer = resources.pointBufferA;
    BigNat xR = resources.ecBigNatB;
    BigNat yR = resources.ecBigNatC;
    BigNat xP = resources.ecBigNatD;
    BigNat yP = resources.ecBigNatE;
    BigNat xQ = resources.ecBigNatF;
    BigNat nominator = resources.ecBigNatB;
    BigNat denominator = resources.ecBigNatC;
    BigNat lambda = resources.ecBigNatA;

    point.getW(pointBuffer, (short) 0);
    xP.setSize(curve.coordinateSize);
    xP.fromByteArray(pointBuffer, (short) 1, curve.coordinateSize);
    yP.setSize(curve.coordinateSize);
    yP.fromByteArray(pointBuffer, (short) (1 + curve.coordinateSize), curve.coordinateSize);

    // l = (y_q-y_p)/(x_q-x_p))
    // x_r = l^2 - x_p -x_q
    // y_r = l(x_p-x_r)-y_p

    // P + Q = R
    if (samePoint) {
      // lambda = (3(x_p^2)+a)/(2y_p)
      // (3(x_p^2)+a)
      nominator.clone(xP);
      nominator.modSq(curve.pValue);
      nominator.modMult(resources.three, curve.pValue);
      nominator.modAdd(curve.aValue, curve.pValue);
      // (2y_p)
      denominator.clone(yP);
      denominator.modMult(resources.two, curve.pValue);
      denominator.modInv(curve.pValue);
    } else {
      // lambda = (y_q-y_p) / (x_q-x_p) mod p
      other.point.getW(pointBuffer, (short) 0);
      xQ.setSize(curve.coordinateSize);
      xQ.fromByteArray(pointBuffer, (short) 1, other.curve.coordinateSize);
      nominator.setSize(curve.coordinateSize);
      nominator.fromByteArray(
        pointBuffer,
        (short) (1 + curve.coordinateSize),
        curve.coordinateSize
      );

      nominator.mod(curve.pValue);

      nominator.modSub(yP, curve.pValue);

      // (x_q-x_p)
      denominator.clone(xQ);
      denominator.mod(curve.pValue);
      denominator.modSub(xP, curve.pValue);
      denominator.modInv(curve.pValue);
    }

    lambda.clone(nominator);
    lambda.modMult(denominator, curve.pValue);

    // (x_p, y_p) + (x_q, y_q) = (x_r, y_r)
    // lambda = (y_q - y_p) / (x_q - x_p)

    // x_r = lambda^2 - x_p - x_q
    if (samePoint) {
      short len = multXKA(resources.two, pointBuffer, (short) 0);

      xR.fromByteArray(pointBuffer, (short) 0, len);
    } else {
      xR.clone(lambda);
      xR.modSq(curve.pValue);
      xR.modSub(xP, curve.pValue);
      xR.modSub(xQ, curve.pValue);
    }

    // y_r = lambda(x_p - x_r) - y_p
    yR.clone(xP);
    yR.modSub(xR, curve.pValue);
    yR.modMult(lambda, curve.pValue);
    yR.modSub(yP, curve.pValue);

    pointBuffer[0] = (byte) 0x04;
    // If x_r.length() and y_r.length() is smaller than curve.coordinateSize due to leading zeroes which were shrunk before, then we must add these back
    xR.prependZeros(curve.coordinateSize, pointBuffer, (short) 1);
    yR.prependZeros(curve.coordinateSize, pointBuffer, (short) (1 + curve.coordinateSize));
    setW(pointBuffer, (short) 0, curve.pointSize);
  }

  /**
   * Implements adding of two points via ALG_EC_PACE_GM.
   *
   * @param other point to be added to this.
   */
  private void hwAdd(ECPoint other) {
    byte[] pointBuffer = resources.pointBufferA;

    setW(
      pointBuffer,
      (short) 0,
      multAndAddKA(resources.oneCoordinate, other, pointBuffer, (short) 0)
    );
  }

  /**
   * Multiply value of this point by provided scalar. Stores the result into this point.
   *
   * @param scalarBytes value of scalar for multiplication
   */
  public void multiplication(byte[] scalarBytes, short scalarOffset, short scalarLen) {
    BigNat scalar = resources.ecBigNatF;

    scalar.setSize(scalarLen);
    scalar.fromByteArray(scalarBytes, scalarOffset, scalarLen);
    multiplication(scalar);
  }

  /**
   * Multiply value of this point by provided scalar. Stores the result into this point.
   *
   * @param scalar value of scalar for multiplication
   */
  public void multiplication(BigNat scalar) {
    if (MathSupport.getInstance().ecSoftwareDouble && scalar.equals(resources.two)) {
      swDouble();
      // } else if (resources.multiplicationAgreement.getAlgorithm() == KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY) {
    } else if (resources.multiplicationAgreement.getAlgorithm() == (byte) 6) {
      multXY(scalar);
      //} else if (resources.multiplicationAgreement.getAlgorithm() == KeyAgreement.ALG_EC_SVDP_DH_PLAIN) {
    } else if (resources.multiplicationAgreement.getAlgorithm() == (byte) 3) {
      multX(scalar);
    } else {
      ISOException.throwIt(MathStatus.SW_OPERATION_NOT_SUPPORTED);
    }
  }

  /**
   * Multiply this point by a given scalar and add another point to the result.
   *
   * @param scalar value of scalar for multiplication
   * @param point the other point
   */
  public void multAndAdd(BigNat scalar, ECPoint point) {
    if (MathSupport.getInstance().ecHardwareAddition) {
      byte[] pointBuffer = resources.pointBufferA;

      setW(pointBuffer, (short) 0, multAndAddKA(scalar, point, pointBuffer, (short) 0));
    } else {
      multiplication(scalar);
      add(point);
    }
  }

  /**
   * Multiply this point by a given scalar and add another point to the result and store the result into outBuffer.
   *
   * @param scalar value of scalar for multiplication
   * @param point the other point
   * @param outBuffer output buffer
   * @param outBufferOffset offset in the output buffer
   */
  private short multAndAddKA(
    BigNat scalar,
    ECPoint point,
    byte[] outBuffer,
    short outBufferOffset
  ) {
    byte[] pointBuffer = resources.pointBufferB;

    short len = getW(pointBuffer, (short) 0);

    curve.sharedPrivateKey.setG(pointBuffer, (short) 0, len);
    scalar.prependZeros((short) curve.r.length, pointBuffer, (short) 0);
    curve.sharedPrivateKey.setS(pointBuffer, (short) 0, (short) curve.r.length);
    resources.additionAgreement.init(curve.sharedPrivateKey);

    len = point.getW(pointBuffer, (short) 0);
    len = resources.additionAgreement.generateSecret(
      pointBuffer,
      (short) 0,
      len,
      outBuffer,
      outBufferOffset
    );

    return len;
  }

  /**
   * Multiply value of this point by provided scalar using XY key agreement. Stores the result into this point.
   *
   * @param scalar value of scalar for multiplication
   */
  public void multXY(BigNat scalar) {
    byte[] pointBuffer = resources.pointBufferA;

    short len = multXYKA(scalar, pointBuffer, (short) 0);

    setW(pointBuffer, (short) 0, len);
  }

  /**
   * Multiplies this point value with provided scalar and stores result into
   * provided array. No modification of this point is performed.
   * Native XY KeyAgreement engine is used.
   *
   * @param scalar          value of scalar for multiplication
   * @param outBuffer       output array for resulting value
   * @param outBufferOffset offset within output array
   * @return length of resulting value (in bytes)
   */
  public short multXYKA(BigNat scalar, byte[] outBuffer, short outBufferOffset) {
    byte[] pointBuffer = resources.pointBufferB;

    scalar.prependZeros((short) curve.r.length, pointBuffer, (short) 0);
    curve.sharedPrivateKey.setS(pointBuffer, (short) 0, (short) curve.r.length);
    resources.multiplicationAgreement.init(curve.sharedPrivateKey);

    short len = getW(pointBuffer, (short) 0);

    len = resources.multiplicationAgreement.generateSecret(
      pointBuffer,
      (short) 0,
      len,
      outBuffer,
      outBufferOffset
    );

    return len;
  }

  /**
   * Multiply value of this point by provided scalar using X-only key agreement. Stores the result into this point.
   *
   * @param scalar value of scalar for multiplication
   */
  private void multX(BigNat scalar) {
    byte[] pointBuffer = resources.pointBufferA;
    byte[] pointBuffer2 = resources.pointBufferB;
    byte[] resultBuffer = resources.bufferA;
    BigNat x = resources.ecBigNatB;
    BigNat ySq = resources.ecBigNatC;
    BigNat y = resources.ecBigNatD;
    BigNat lambda = resources.ecBigNatE;
    BigNat tmp = resources.ecBigNatF;
    BigNat denominator = resources.ecBigNatD;

    short len = multXKA(scalar, pointBuffer, (short) 0);

    x.fromByteArray(pointBuffer, (short) 0, len);

    // Solve for Y in Weierstrass equation: Y^2 = X^3 + XA + B = x(x^2+A)+B
    ySq.clone(x);
    ySq.modExp(resources.two, curve.pValue);
    ySq.modAdd(curve.aValue, curve.pValue);
    ySq.modMult(x, curve.pValue);
    ySq.modAdd(curve.bValue, curve.pValue);
    y.clone(ySq);
    y.modSqrt(curve.pValue);

    // Construct public key with <x, y>
    pointBuffer[0] = 0x04;
    x.prependZeros(curve.coordinateSize, pointBuffer, (short) 1);
    y.prependZeros(curve.coordinateSize, pointBuffer, (short) (1 + curve.coordinateSize));

    boolean negate;

    if (MathSupport.getInstance().ecHardwareXECDSA) {
      getW(pointBuffer2, (short) 0);
      curve.sharedPrivateKey.setG(pointBuffer2, (short) 0, curve.pointSize);
      curve.sharedPublicKey.setG(pointBuffer2, (short) 0, curve.pointSize);

      setW(pointBuffer, (short) 0, curve.pointSize);

      // Check if <x, y> corresponds to the "secret" (i.e., our scalar)
      scalar.prependZeros((short) curve.r.length, resultBuffer, (short) 0);
      curve.sharedPrivateKey.setS(resultBuffer, (short) 0, (short) curve.r.length);
      curve.sharedPublicKey.setW(pointBuffer, (short) 0, curve.pointSize);
      negate = !signVerifyECDSA(
        curve.sharedPrivateKey,
        curve.sharedPublicKey,
        resources.ecdsaVerification,
        resultBuffer
      );
    } else {
      // Check that (<x, y> + P)_x == ((scalar + 1)P)_x
      scalar.increment();
      len = multXKA(scalar, resultBuffer, (short) 0);
      x.fromByteArray(resultBuffer, (short) 0, len);
      scalar.decrement(); // keep the original

      getW(pointBuffer2, (short) 0);
      setW(pointBuffer, (short) 0, curve.pointSize);

      // y_1 - y_2
      lambda.fromByteArray(pointBuffer2, (short) (1 + curve.coordinateSize), curve.coordinateSize);
      tmp.fromByteArray(pointBuffer, (short) (1 + curve.coordinateSize), curve.coordinateSize);
      lambda.modSub(tmp, curve.pValue);

      // (x_1 - x_2)^-1
      denominator.fromByteArray(pointBuffer2, (short) 1, curve.coordinateSize);
      tmp.fromByteArray(pointBuffer, (short) 1, curve.coordinateSize);
      denominator.modSub(tmp, curve.pValue);
      denominator.modInv(curve.pValue);

      // λ = (y_1 - y_2)/(x_1 - x_2)
      lambda.modMult(denominator, curve.pValue);

      // x_3 = λ^2 - x_1 - x_2
      lambda.modSq(curve.pValue);
      tmp.fromByteArray(pointBuffer2, (short) 1, curve.coordinateSize);
      lambda.modSub(tmp, curve.pValue);
      tmp.fromByteArray(pointBuffer, (short) 1, curve.coordinateSize);
      lambda.modSub(tmp, curve.pValue);

      // If <x, y> + P != (scalar + 1)P, negate the point
      negate = !lambda.equals(x);
    }

    if (negate) {
      negate();
    }
  }

  /**
   * Multiplies this point value with provided scalar and stores result into
   * provided array. No modification of this point is performed.
   * Native X-only KeyAgreement engine is used.
   *
   * @param scalar          value of scalar for multiplication
   * @param outBuffer       output array for resulting value
   * @param outBufferOffset offset within output array
   * @return length of resulting value (in bytes)
   */
  private short multXKA(BigNat scalar, byte[] outBuffer, short outBufferOffset) {
    byte[] pointBuffer = resources.pointBufferB;

    // NOTE: potential problem on real cards (j2e) - when small scalar is used (e.g., BigNat.TWO), operation sometimes freezes
    scalar.prependZeros((short) curve.r.length, pointBuffer, (short) 0);
    curve.sharedPrivateKey.setS(pointBuffer, (short) 0, (short) curve.r.length);

    resources.multiplicationAgreement.init(curve.sharedPrivateKey);

    short len = getW(pointBuffer, (short) 0);

    resources.multiplicationAgreement.generateSecret(
      pointBuffer,
      (short) 0,
      len,
      outBuffer,
      outBufferOffset
    );

    // Return always length of whole coordinate X instead of len - some real cards returns shorter value equal to SHA-1 output size although PLAIN results is filled into buffer (GD60)
    return curve.coordinateSize;
  }

  /**
   * Computes negation of this point.
   * The operation will dump point into uncompressed_point_arr, negate Y and restore back
   */
  public void negate() {
    byte[] pointBuffer = resources.pointBufferA;
    BigNat y = resources.ecBigNatC;

    point.getW(pointBuffer, (short) 0);
    y.setSize(curve.coordinateSize);
    y.fromByteArray(pointBuffer, (short) (1 + curve.coordinateSize), curve.coordinateSize);
    y.modNegate(curve.pValue);
    y.prependZeros(curve.coordinateSize, pointBuffer, (short) (1 + curve.coordinateSize));
    setW(pointBuffer, (short) 0, curve.pointSize);
  }

  /**
   * Restore point from X coordinate. Stores one of the two results into this point.
   *
   * @param xCoord  byte array containing the X coordinate
   * @param xOffset offset in the byte array
   * @param xLen    length of the X coordinate
   */
  public void fromX(byte[] xCoord, short xOffset, short xLen) {
    BigNat x = resources.ecBigNatF;

    x.setSize(xLen);
    x.fromByteArray(xCoord, xOffset, xLen);
    fromX(x);
  }

  /**
   * Restore point from X coordinate. Stores one of the two results into this point.
   *
   * @param x the x coordinate
   */
  private void fromX(BigNat x) {
    BigNat ySq = resources.ecBigNatC;
    BigNat y = resources.ecBigNatD;
    byte[] pointBuffer = resources.pointBufferA;

    //Y^2 = X^3 + XA + B = x(x^2+A)+B
    ySq.clone(x);
    ySq.modSq(curve.pValue);
    ySq.modAdd(curve.aValue, curve.pValue);
    ySq.modMult(x, curve.pValue);
    ySq.modAdd(curve.bValue, curve.pValue);
    y.clone(ySq);
    y.modSqrt(curve.pValue);

    // Construct public key with <x, y_1>
    pointBuffer[0] = 0x04;
    x.prependZeros(curve.coordinateSize, pointBuffer, (short) 1);
    y.prependZeros(curve.coordinateSize, pointBuffer, (short) (1 + curve.coordinateSize));
    setW(pointBuffer, (short) 0, curve.pointSize);
  }

  /**
   * Returns true if Y coordinate is even; false otherwise.
   *
   * @return true if Y coordinate is even; false otherwise
   */
  public boolean isYEven() {
    byte[] pointBuffer = resources.pointBufferA;

    point.getW(pointBuffer, (short) 0);
    boolean result = pointBuffer[(short) (curve.pointSize - 1)] % 2 == 0;

    return result;
  }

  /**
   * Compares this and provided point for equality. The comparison is made using hash of both values to prevent leak of position of mismatching byte.
   *
   * @param other second point for comparison
   * @return true if both point are exactly equal (same length, same value), false otherwise
   */
  public boolean isEqual(ECPoint other) {
    if (length() != other.length()) {
      return false;
    }

    // The comparison is made with hash of point values instead of directly values.
    // This way, offset of first mismatching byte is not leaked via timing side-channel.
    // Additionally, only single array is required for storage of plain point values thus saving some RAM.
    byte[] pointBuffer = resources.pointBufferA;
    byte[] hashBuffer = resources.hashBuffer;

    short len = getW(pointBuffer, (short) 0);

    resources.hashEngine.doFinal(pointBuffer, (short) 0, len, hashBuffer, (short) 0);
    len = other.getW(pointBuffer, (short) 0);
    len = resources.hashEngine.doFinal(pointBuffer, (short) 0, len, pointBuffer, (short) 0);
    return Util.arrayCompare(hashBuffer, (short) 0, pointBuffer, (short) 0, len) == 0;
  }

  public static boolean signVerifyECDSA(
    ECPrivateKey privateKey,
    ECPublicKey publicKey,
    Signature signEngine,
    byte[] tmpSignArray
  ) {
    signEngine.init(privateKey, Signature.MODE_SIGN);
    short signLen = signEngine.sign(
      ECDSA_TEST_MESSAGE,
      (short) 0,
      (short) ECDSA_TEST_MESSAGE.length,
      tmpSignArray,
      (short) 0
    );

    signEngine.init(publicKey, Signature.MODE_VERIFY);

    return signEngine.verify(
      ECDSA_TEST_MESSAGE,
      (short) 0,
      (short) ECDSA_TEST_MESSAGE.length,
      tmpSignArray,
      (short) 0,
      signLen
    );
  }

  /**
   * Decode SEC1-encoded point and load it into this.
   *
   * @param point array containing SEC1-encoded point
   * @param offset offset within the output buffer
   * @param length length of the encoded point
   * @return true if the point was compressed; false otherwise
   */
  public boolean decode(byte[] point, short offset, short length) {
    if (length == (short) (1 + 2 * curve.coordinateSize) && point[offset] == 0x04) {
      setW(point, offset, length);

      return false;
    }

    if (length == (short) (1 + curve.coordinateSize)) {
      BigNat y = resources.ecBigNatC;
      BigNat x = resources.ecBigNatD;
      BigNat p = resources.ecBigNatE;
      byte[] pointBuffer = resources.pointBufferA;

      x.fromByteArray(point, (short) (offset + 1), curve.coordinateSize);

      //Y^2 = X^3 + XA + B = x(x^2+A)+B
      y.clone(x);
      y.modSq(curve.pValue);
      y.modAdd(curve.aValue, curve.pValue);
      y.modMult(x, curve.pValue);
      y.modAdd(curve.bValue, curve.pValue);
      y.modSqrt(curve.pValue);

      pointBuffer[0] = 0x04;
      x.prependZeros(curve.coordinateSize, pointBuffer, (short) 1);

      boolean odd = y.isOdd();

      if ((!odd && point[offset] != (byte) 0x02) || (odd && point[offset] != (byte) 0x03)) {
        p.clone(curve.pValue);
        p.subtract(y);
        p.prependZeros(curve.coordinateSize, pointBuffer, (short) (curve.coordinateSize + 1));
      } else {
        y.prependZeros(curve.coordinateSize, pointBuffer, (short) (curve.coordinateSize + 1));
      }

      setW(pointBuffer, (short) 0, curve.pointSize);

      return true;
    }

    ISOException.throwIt(MathStatus.SW_EC_POINT_INVALID);

    return true; // unreachable
  }

  /**
   * Encode this point into the output buffer.
   *
   * @param output output buffer; MUST be able to store offset + uncompressed size bytes
   * @param offset offset within the output buffer
   * @param compressed output compressed point if true; uncompressed otherwise
   * @return length of output point
   */
  public short encode(byte[] output, short offset, boolean compressed) {
    getW(output, offset);

    if (compressed) {
      if (output[offset] == (byte) 0x04) {
        output[offset] = (byte) (((output[(short) (offset + 2 * curve.coordinateSize)] & 0xFF) %
              2) ==
            0
            ? 2
            : 3);
      }

      return (short) (curve.coordinateSize + 1);
    }

    if (output[offset] != (byte) 0x04) {
      BigNat y = resources.ecBigNatC;
      BigNat x = resources.ecBigNatD;
      BigNat p = resources.ecBigNatE;

      x.fromByteArray(output, (short) (offset + 1), curve.coordinateSize);

      //Y^2 = X^3 + XA + B = x(x^2+A)+B
      y.clone(x);
      y.modSq(curve.pValue);
      y.modAdd(curve.aValue, curve.pValue);
      y.modMult(x, curve.pValue);
      y.modAdd(curve.bValue, curve.pValue);
      y.modSqrt(curve.pValue);
      boolean odd = y.isOdd();

      if ((!odd && output[offset] != (byte) 0x02) || (odd && output[offset] != (byte) 0x03)) {
        p.clone(curve.pValue);
        p.subtract(y);
        p.prependZeros(curve.coordinateSize, output, (short) (offset + curve.coordinateSize + 1));
      } else {
        y.prependZeros(curve.coordinateSize, output, (short) (offset + curve.coordinateSize + 1));
      }

      output[offset] = (byte) 0x04;
    }

    return (short) (2 * curve.coordinateSize + 1);
  }

  //
  // ECKey methods
  //
  public void setFieldFP(byte[] bytes, short s, short s1) throws CryptoException {
    point.setFieldFP(bytes, s, s1);
  }

  public void setFieldF2M(short s) throws CryptoException {
    point.setFieldF2M(s);
  }

  public void setFieldF2M(short s, short s1, short s2) throws CryptoException {
    point.setFieldF2M(s, s1, s2);
  }

  public void setA(byte[] bytes, short s, short s1) throws CryptoException {
    point.setA(bytes, s, s1);
  }

  public void setB(byte[] bytes, short s, short s1) throws CryptoException {
    point.setB(bytes, s, s1);
  }

  public void setG(byte[] bytes, short s, short s1) throws CryptoException {
    point.setG(bytes, s, s1);
  }

  public void setR(byte[] bytes, short s, short s1) throws CryptoException {
    point.setR(bytes, s, s1);
  }

  public void setK(short s) {
    point.setK(s);
  }

  public short getField(byte[] bytes, short s) throws CryptoException {
    return point.getField(bytes, s);
  }

  public short getA(byte[] bytes, short s) throws CryptoException {
    return point.getA(bytes, s);
  }

  public short getB(byte[] bytes, short s) throws CryptoException {
    return point.getB(bytes, s);
  }

  public short getG(byte[] bytes, short s) throws CryptoException {
    return point.getG(bytes, s);
  }

  public short getR(byte[] bytes, short s) throws CryptoException {
    return point.getR(bytes, s);
  }

  public short getK() throws CryptoException {
    return point.getK();
  }
}
