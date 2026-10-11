// Derived from JCEd25519 / JCMathLib 2.1-rc.1 (MIT).
// Copyright (c) 2022 Antonin Dufka; JCMathLib authors Vasilios Mavroudis, Petr Svenda, Antonin Dufka.
// Source, changes and licenses: third-party/jced25519/PROVENANCE.md.
package monoid;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public final class MathResources {

  public MathAllocator allocator;

  MessageDigest hashEngine;
  KeyAgreement multiplicationAgreement;
  KeyAgreement additionAgreement;
  Signature ecdsaVerification;
  Cipher squareCipher;
  Cipher modularSquareCipher;
  Cipher exponentiationCipher;
  RSAPublicKey squarePublicKey;
  RSAPublicKey modularSquarePublicKey;
  RSAPublicKey exponentiationPublicKey;
  RSAPrivateKey squarePrivateKey;
  RSAPrivateKey modularSquarePrivateKey;
  RSAPrivateKey exponentiationPrivateKey;
  BigNat fixedModulus;

  byte[] bufferA;
  byte[] bufferB;
  byte[] pointBufferA;
  byte[] pointBufferB;
  byte[] hashBuffer;

  static final byte[] CONST_ONE = { 0x01 };
  static final byte[] CONST_TWO = { 0x02 };

  BigNat word;
  BigNat bigNatA;
  BigNat bigNatB;
  BigNat bigNatC;
  BigNat bigNatD;
  BigNat bigNatE;
  BigNat bigNatF;
  BigNat bigNatG;
  BigNat ecBigNatA;
  BigNat ecBigNatB;
  BigNat ecBigNatC;
  BigNat ecBigNatD;
  BigNat ecBigNatE;
  BigNat ecBigNatF;
  // These numbers retain their resource manager. Instance ownership allows the
  // entire math context to be collected when switching signing algorithms.
  public final BigNat two;
  public final BigNat three;
  public final BigNat oneCoordinate;

  public final short maxExponentBitLength;
  public final short maxExponentLength;
  public final short maxSquareBitLength;
  public final short maxSquareLength;
  public final short maxBigNatSize;
  public final short maxPointSize;
  public final short maxCoordinateSize;

  public MathResources(short maxEcLength) {
    short min = MathSupport.getInstance().minRSABitLength;

    if (maxEcLength <= (short) 256) {
      maxExponentBitLength = (short) 512 < min ? min : (short) 512;
      maxSquareBitLength = (short) 768 < min ? min : (short) 768;
      maxPointSize = (short) 64;
    } else if (maxEcLength <= (short) 384) {
      maxExponentBitLength = (short) 768 < min ? min : (short) 768;
      maxSquareBitLength = (short) 1024 < min ? min : (short) 1024;
      maxPointSize = (short) 96;
    } else if (maxEcLength <= (short) 512) {
      maxExponentBitLength = (short) 1024 < min ? min : (short) 1024;
      maxSquareBitLength = (short) 1280 < min ? min : (short) 1280;
      maxPointSize = (short) 128;
    } else {
      maxExponentBitLength = (short) 0;
      maxSquareBitLength = (short) 0;
      maxPointSize = (short) 0;
      ISOException.throwIt(MathStatus.SW_EC_POINT_INVALID_LENGTH);
    }

    maxSquareLength = (short) (maxSquareBitLength / 8);
    maxExponentLength = (short) (maxExponentBitLength / 8);
    maxBigNatSize = (short) (maxExponentBitLength / 8);
    maxCoordinateSize = (short) (maxPointSize / 2);

    allocator = new MathAllocator();
    allocator.setAllAllocatorsRAM();

    bufferA = allocator.allocateByteArray(
      maxSquareLength,
      allocator.getAllocatorType(MathAllocator.ARRAY_A)
    );
    bufferB = allocator.allocateByteArray(
      maxSquareLength,
      allocator.getAllocatorType(MathAllocator.ARRAY_B)
    );
    pointBufferA = allocator.allocateByteArray(
      (short) (maxPointSize + 1),
      allocator.getAllocatorType(MathAllocator.POINT_ARRAY_A)
    );
    pointBufferB = allocator.allocateByteArray(
      (short) (maxPointSize + 1),
      allocator.getAllocatorType(MathAllocator.POINT_ARRAY_B)
    );
    hashEngine = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    hashBuffer = allocator.allocateByteArray(
      hashEngine.getLength(),
      allocator.getAllocatorType(MathAllocator.HASH_ARRAY)
    );

    word = new BigNat((short) 2, allocator.getAllocatorType(MathAllocator.BN_WORD), this);

    bigNatA = new BigNat(maxBigNatSize, allocator.getAllocatorType(MathAllocator.BN_A), this);
    bigNatB = new BigNat(maxBigNatSize, allocator.getAllocatorType(MathAllocator.BN_B), this);
    bigNatC = new BigNat(maxBigNatSize, allocator.getAllocatorType(MathAllocator.BN_C), this);
    bigNatD = new BigNat(maxBigNatSize, allocator.getAllocatorType(MathAllocator.BN_D), this);
    bigNatE = new BigNat(maxBigNatSize, allocator.getAllocatorType(MathAllocator.BN_E), this);
    bigNatF = new BigNat(maxSquareLength, allocator.getAllocatorType(MathAllocator.BN_F), this);
    bigNatG = new BigNat(maxSquareLength, allocator.getAllocatorType(MathAllocator.BN_G), this);

    ecBigNatA = new BigNat(maxPointSize, allocator.getAllocatorType(MathAllocator.EC_BN_A), this);
    ecBigNatB = new BigNat(
      maxCoordinateSize,
      allocator.getAllocatorType(MathAllocator.EC_BN_B),
      this
    );
    ecBigNatC = new BigNat(
      maxCoordinateSize,
      allocator.getAllocatorType(MathAllocator.EC_BN_C),
      this
    );
    ecBigNatD = new BigNat(
      maxCoordinateSize,
      allocator.getAllocatorType(MathAllocator.EC_BN_D),
      this
    );
    ecBigNatE = new BigNat(
      maxCoordinateSize,
      allocator.getAllocatorType(MathAllocator.EC_BN_E),
      this
    );
    ecBigNatF = new BigNat(
      maxCoordinateSize,
      allocator.getAllocatorType(MathAllocator.EC_BN_F),
      this
    );

    // Allocate BN constants always in EEPROM (only reading)
    two = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
    two.setValue((byte) 2);
    three = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
    three.setValue((byte) 3);
    oneCoordinate = new BigNat(maxCoordinateSize, JCSystem.MEMORY_TYPE_PERSISTENT, this);
    oneCoordinate.setValue((byte) 1);

    // ECC Helpers
    if (MathSupport.getInstance().ecHardwareXY) {
      multiplicationAgreement = KeyAgreement.getInstance(
        KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY,
        false
      );
    } else if (MathSupport.getInstance().ecHardwareX) {
      multiplicationAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    }

    ecdsaVerification = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

    if (MathSupport.getInstance().ecHardwareAddition) {
      additionAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_PACE_GM, false);
    }

    // RSA Sq Helpers
    if (MathSupport.getInstance().rsaSquaring) {
      Util.arrayFillNonAtomic(bufferA, (short) 0, maxSquareLength, (byte) 0xFF);
      squareCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
      modularSquareCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

      if (MathSupport.getInstance().rsaPublicKey) {
        modularSquarePublicKey = (RSAPublicKey) KeyBuilder.buildKey(
          KeyBuilder.TYPE_RSA_PUBLIC,
          maxExponentBitLength,
          false
        );
        squarePublicKey = (RSAPublicKey) KeyBuilder.buildKey(
          KeyBuilder.TYPE_RSA_PUBLIC,
          maxSquareBitLength,
          false
        );
        squarePublicKey.setExponent(CONST_TWO, (short) 0, (short) CONST_TWO.length);
        squarePublicKey.setModulus(bufferA, (short) 0, maxSquareLength);
        squareCipher.init(squarePublicKey, Cipher.MODE_ENCRYPT);
      } else {
        modularSquarePrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(
          KeyBuilder.TYPE_RSA_PRIVATE,
          maxExponentBitLength,
          false
        );
        squarePrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(
          KeyBuilder.TYPE_RSA_PRIVATE,
          maxSquareBitLength,
          false
        );
        squarePrivateKey.setExponent(CONST_TWO, (short) 0, (short) CONST_TWO.length);
        squarePrivateKey.setModulus(bufferA, (short) 0, maxSquareLength);
        squareCipher.init(squarePrivateKey, Cipher.MODE_DECRYPT);
      }
    }

    // RSA Exp Helpers
    exponentiationPublicKey = (RSAPublicKey) KeyBuilder.buildKey(
      KeyBuilder.TYPE_RSA_PUBLIC,
      maxExponentBitLength,
      false
    );
    exponentiationPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(
      KeyBuilder.TYPE_RSA_PRIVATE,
      maxExponentBitLength,
      false
    );
    exponentiationCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
  }

  /**
   * Preloads modSq engine with a given mod. Can increase performance when the same mod is used repeatedly. The
   * provided mod is assumed to be fixed.
   */
  public void fixModSqMod(BigNat mod) {
    if (!MathSupport.getInstance().rsaSquaring) {
      return; // modSq engine is not used
    }

    fixedModulus = mod;

    if (mod == null) {
      return;
    }

    BigNat tmpMod = bigNatF;
    byte[] tmpBuffer = bufferA;

    tmpMod.setSize(maxExponentLength);

    if (MathSupport.getInstance().rsaPublicKey) {
      if (MathSupport.getInstance().rsaKeyRefresh) {
        modularSquarePublicKey = (RSAPublicKey) KeyBuilder.buildKey(
          KeyBuilder.TYPE_RSA_PUBLIC,
          maxExponentBitLength,
          false
        );
      }

      modularSquarePublicKey.setExponent(
        MathResources.CONST_TWO,
        (short) 0,
        (short) MathResources.CONST_TWO.length
      );

      if (MathSupport.getInstance().rsaResizeModulus) {
        if (MathSupport.getInstance().rsaAppendModulus) {
          mod.appendZeros(maxExponentLength, tmpBuffer, (short) 0);
        } else {
          mod.prependZeros(maxExponentLength, tmpBuffer, (short) 0);
        }

        modularSquarePublicKey.setModulus(tmpBuffer, (short) 0, maxExponentLength);
      } else {
        short modLength = mod.copyToByteArray(tmpBuffer, (short) 0);

        modularSquarePublicKey.setModulus(tmpBuffer, (short) 0, modLength);
      }

      modularSquareCipher.init(modularSquarePublicKey, Cipher.MODE_DECRYPT);
    } else {
      if (MathSupport.getInstance().rsaKeyRefresh) {
        modularSquarePrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(
          KeyBuilder.TYPE_RSA_PRIVATE,
          maxExponentBitLength,
          false
        );
      }

      modularSquarePrivateKey.setExponent(
        MathResources.CONST_TWO,
        (short) 0,
        (short) MathResources.CONST_TWO.length
      );

      if (MathSupport.getInstance().rsaResizeModulus) {
        if (MathSupport.getInstance().rsaAppendModulus) {
          mod.appendZeros(maxExponentLength, tmpBuffer, (short) 0);
        } else {
          mod.prependZeros(maxExponentLength, tmpBuffer, (short) 0);
        }

        modularSquarePrivateKey.setModulus(tmpBuffer, (short) 0, maxExponentLength);
      } else {
        short modLength = mod.copyToByteArray(tmpBuffer, (short) 0);

        modularSquarePrivateKey.setModulus(tmpBuffer, (short) 0, modLength);
      }

      modularSquareCipher.init(modularSquarePrivateKey, Cipher.MODE_DECRYPT);
    }
  }

  /**
   * Erase all values stored in helper objects
   */
  void erase() {
    word.erase();

    bigNatA.erase();
    bigNatB.erase();
    bigNatC.erase();
    bigNatD.erase();
    bigNatE.erase();
    bigNatF.erase();
    bigNatG.erase();

    ecBigNatA.erase();
    ecBigNatB.erase();
    ecBigNatC.erase();
    ecBigNatD.erase();
    ecBigNatE.erase();
    ecBigNatF.erase();

    Util.arrayFillNonAtomic(bufferA, (short) 0, (short) bufferA.length, (byte) 0);
    Util.arrayFillNonAtomic(bufferB, (short) 0, (short) bufferB.length, (byte) 0);
    Util.arrayFillNonAtomic(pointBufferA, (short) 0, (short) pointBufferA.length, (byte) 0);
    Util.arrayFillNonAtomic(pointBufferB, (short) 0, (short) pointBufferB.length, (byte) 0);
    Util.arrayFillNonAtomic(hashBuffer, (short) 0, (short) hashBuffer.length, (byte) 0);
  }
}
