// Derived from JCEd25519 / JCMathLib 2.1-rc.1 (MIT).
// Copyright (c) 2022 Antonin Dufka; JCMathLib authors Vasilios Mavroudis, Petr Svenda, Antonin Dufka.
// Source, changes and licenses: third-party/jced25519/PROVENANCE.md.
package monoid;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

public final class BigNat extends BigNatInternal {

  /**
   * Construct a BigNat of a given size in bytes.
   */
  public BigNat(short size, byte allocatorType, MathResources resources) {
    super(size, allocatorType, resources);
  }

  /**
   * Division of this BigNat by provided other BigNat.
   */
  public void divide(BigNat other) {
    BigNat tmp = resources.bigNatE;

    tmp.clone(this);
    tmp.remainderDivide(other, this);
    copy(tmp);
  }

  /**
   * Greatest common divisor of this BigNat with other BigNat. Result is stored into this.
   */
  public void gcd(BigNat other) {
    BigNat tmp = resources.bigNatA;
    BigNat tmpOther = resources.bigNatB;

    tmpOther.clone(other);

    // TODO: optimise?
    while (!other.equals((byte) 0)) {
      tmp.clone(tmpOther);
      mod(tmpOther);
      tmpOther.clone(this);
      clone(tmp);
    }
  }

  /**
   * Decides whether the arguments are co-prime or not.
   */
  public boolean isCoprime(BigNat a, BigNat b) {
    BigNat tmp = resources.bigNatC;

    tmp.clone(a);

    tmp.gcd(b);
    boolean result = tmp.equals((byte) 1);

    return result;
  }

  /**
   * Square computation supporting base greater than MAX_BIGNAT_LENGTH.
   */
  public void sq() {
    if (!MathSupport.getInstance().rsaSquaring) {
      BigNat tmp = resources.bigNatE;

      tmp.setSize(length());
      tmp.copy(this);
      super.mult(tmp);

      return;
    }

    if ((short) (resources.maxSquareLength - 1) < (short) (2 * length())) {
      ISOException.throwIt(MathStatus.SW_BIG_NAT_INVALID_SQUARE);
    }

    byte[] resultBuffer = resources.bufferA;
    short offset = (short) (resources.maxSquareLength - length());

    Util.arrayFillNonAtomic(resultBuffer, (short) 0, offset, (byte) 0x00);
    copyToByteArray(resultBuffer, offset);
    short len = resources.squareCipher.doFinal(
      resultBuffer,
      (short) 0,
      resources.maxSquareLength,
      resultBuffer,
      (short) 0
    );

    if (len != resources.maxSquareLength) {
      if (MathSupport.getInstance().rsaPrependZeros) {
        Util.arrayCopyNonAtomic(
          resultBuffer,
          (short) 0,
          resultBuffer,
          (short) (resources.maxSquareLength - len),
          len
        );
        Util.arrayFillNonAtomic(
          resultBuffer,
          (short) 0,
          (short) (resources.maxSquareLength - len),
          (byte) 0
        );
      } else {
        ISOException.throwIt(MathStatus.SW_EC_POINT_UNEXPECTED_AGREEMENT_LENGTH);
      }
    }

    short zeroPrefix = (short) (resources.maxSquareLength - (short) 2 * length());

    fromByteArray(resultBuffer, zeroPrefix, (short) (resources.maxSquareLength - zeroPrefix));
    shrink();
  }

  /**
   * Computes this * other and stores the result into this.
   */
  public void mult(BigNat other) {
    if (MathSupport.getInstance().rsaCheckOne && equals((byte) 1)) {
      clone(other);

      return;
    }

    if (!MathSupport.getInstance().rsaSquaring || length() <= (short) 16) {
      super.mult(other);

      return;
    }

    BigNat result = resources.bigNatF;
    BigNat tmp = resources.bigNatG;

    result.setSize((short) ((length() > other.length() ? length() : other.length()) + 1));
    result.copy(this);
    result.add(other);
    result.sq();

    if (isLesser(other)) {
      tmp.clone(other);
      tmp.subtract(this);
    } else {
      tmp.clone(this);
      tmp.subtract(other);
    }

    tmp.sq();

    result.subtract(tmp);
    result.shiftRight((short) 2);

    setSizeToMax(false);
    copy(result);
    shrink();
  }

  /**
   * Computes modulo and stores the result in this.
   */
  public void mod(BigNat mod) {
    remainderDivide(mod, null);
  }

  /**
   * Negate current BigNat modulo provided modulus.
   */
  public void modNegate(BigNat mod) {
    BigNat tmp = resources.bigNatB;

    tmp.clone(mod);
    tmp.subtract(this);
    setSize(mod.length());
    copy(tmp);
  }

  /**
   * Modular addition of a BigNat to this.
   */
  public void modAdd(BigNat other, BigNat mod) {
    resize((short) (mod.length() + 1));
    add(other);

    if (!isLesser(mod)) {
      subtract(mod);
    }

    setSize(mod.length());
  }

  /**
   * Modular subtraction of a BigNat from this.
   */
  public void modSub(BigNat other, BigNat mod) {
    resize((short) (mod.length() + 1));

    if (isLesser(other)) {
      add(mod);
    }

    subtract(other);
    setSize(mod.length());
  }

  /**
   * Square this mod a modulus fixed with fixModSqMod method.
   */
  private void modSqFixed() {
    BigNat tmpMod = resources.bigNatF;
    byte[] tmpBuffer = resources.bufferA;
    short modLength;

    tmpMod.setSize(resources.maxExponentLength);

    if (MathSupport.getInstance().rsaResizeModulus) {
      modLength = resources.maxExponentLength;
    } else {
      modLength = resources.fixedModulus.length();
    }

    prependZeros(modLength, tmpBuffer, (short) 0);
    short len = resources.modularSquareCipher.doFinal(
      tmpBuffer,
      (short) 0,
      modLength,
      tmpBuffer,
      (short) 0
    );

    if (len != resources.maxExponentLength) {
      if (MathSupport.getInstance().rsaPrependZeros) {
        Util.arrayCopyNonAtomic(
          tmpBuffer,
          (short) 0,
          tmpBuffer,
          (short) (resources.maxExponentLength - len),
          len
        );
        Util.arrayFillNonAtomic(
          tmpBuffer,
          (short) 0,
          (short) (resources.maxExponentLength - len),
          (byte) 0
        );
      } else {
        ISOException.throwIt(MathStatus.SW_EC_POINT_UNEXPECTED_AGREEMENT_LENGTH);
      }
    }

    tmpMod.fromByteArray(tmpBuffer, (short) 0, resources.maxExponentLength);

    if (MathSupport.getInstance().rsaExtraModulo) {
      tmpMod.mod(resources.fixedModulus);
    }

    setSize(resources.fixedModulus.length());
    copy(tmpMod);
  }

  /**
   * Computes (this ^ exp % mod) using RSA algorithm and store results into this.
   */
  public void modExp(BigNat exp, BigNat mod) {
    if (!MathSupport.getInstance().rsaExponentiation) {
      ISOException.throwIt(MathStatus.SW_OPERATION_NOT_SUPPORTED);
    }

    if (MathSupport.getInstance().rsaCheckExponentOne && exp.equals((byte) 1)) {
      return;
    }

    if (!MathSupport.getInstance().rsaSquaring && exp.equals((byte) 2)) {
      modMult(this, mod);

      return;
    }

    BigNat tmpMod = resources.bigNatF; // modExp is called from modSqrt => requires BN_F not being locked when modExp is called
    byte[] tmpBuffer = resources.bufferA;
    short modLength;

    tmpMod.setSize(resources.maxExponentLength);

    if (MathSupport.getInstance().rsaPublicKey) {
      // Verify if pre-allocated engine match the required values
      if (
        resources.exponentiationPublicKey.getSize() < (short) (mod.length() * 8) ||
        resources.exponentiationPublicKey.getSize() < (short) (length() * 8)
      ) {
        ISOException.throwIt(MathStatus.SW_BIG_NAT_MODULUS_TOO_LARGE);
      }

      if (MathSupport.getInstance().rsaKeyRefresh) {
        // Simulator fails when reusing the original object
        resources.exponentiationPublicKey = (RSAPublicKey) KeyBuilder.buildKey(
          KeyBuilder.TYPE_RSA_PUBLIC,
          resources.maxExponentBitLength,
          false
        );
      }

      short len = exp.copyToByteArray(tmpBuffer, (short) 0);

      resources.exponentiationPublicKey.setExponent(tmpBuffer, (short) 0, len);

      if (MathSupport.getInstance().rsaResizeModulus) {
        if (MathSupport.getInstance().rsaAppendModulus) {
          mod.appendZeros(resources.maxExponentLength, tmpBuffer, (short) 0);
        } else {
          mod.prependZeros(resources.maxExponentLength, tmpBuffer, (short) 0);
        }

        resources.exponentiationPublicKey.setModulus(
          tmpBuffer,
          (short) 0,
          resources.maxExponentLength
        );
        modLength = resources.maxExponentLength;
      } else {
        modLength = mod.copyToByteArray(tmpBuffer, (short) 0);
        resources.exponentiationPublicKey.setModulus(tmpBuffer, (short) 0, modLength);
      }

      resources.exponentiationCipher.init(resources.exponentiationPublicKey, Cipher.MODE_DECRYPT);
    } else {
      // Verify if pre-allocated engine match the required values
      if (
        resources.exponentiationPrivateKey.getSize() < (short) (mod.length() * 8) ||
        resources.exponentiationPrivateKey.getSize() < (short) (length() * 8)
      ) {
        ISOException.throwIt(MathStatus.SW_BIG_NAT_MODULUS_TOO_LARGE);
      }

      if (MathSupport.getInstance().rsaKeyRefresh) {
        // Simulator fails when reusing the original object
        resources.exponentiationPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(
          KeyBuilder.TYPE_RSA_PRIVATE,
          resources.maxExponentBitLength,
          false
        );
      }

      short len = exp.copyToByteArray(tmpBuffer, (short) 0);

      resources.exponentiationPrivateKey.setExponent(tmpBuffer, (short) 0, len);

      if (MathSupport.getInstance().rsaResizeModulus) {
        if (MathSupport.getInstance().rsaAppendModulus) {
          mod.appendZeros(resources.maxExponentLength, tmpBuffer, (short) 0);
        } else {
          mod.prependZeros(resources.maxExponentLength, tmpBuffer, (short) 0);
        }

        resources.exponentiationPrivateKey.setModulus(
          tmpBuffer,
          (short) 0,
          resources.maxExponentLength
        );
        modLength = resources.maxExponentLength;
      } else {
        modLength = mod.copyToByteArray(tmpBuffer, (short) 0);
        resources.exponentiationPrivateKey.setModulus(tmpBuffer, (short) 0, modLength);
      }

      resources.exponentiationCipher.init(resources.exponentiationPrivateKey, Cipher.MODE_DECRYPT);
    }

    prependZeros(modLength, tmpBuffer, (short) 0);
    short len = resources.exponentiationCipher.doFinal(
      tmpBuffer,
      (short) 0,
      modLength,
      tmpBuffer,
      (short) 0
    );

    if (len != resources.maxExponentLength) {
      if (MathSupport.getInstance().rsaPrependZeros) {
        // Decrypted length can be either tmp_size or less because of leading zeroes consumed by simulator engine implementation
        // Move obtained value into proper position with zeroes prepended
        Util.arrayCopyNonAtomic(
          tmpBuffer,
          (short) 0,
          tmpBuffer,
          (short) (resources.maxExponentLength - len),
          len
        );
        Util.arrayFillNonAtomic(
          tmpBuffer,
          (short) 0,
          (short) (resources.maxExponentLength - len),
          (byte) 0
        );
      } else {
        // real cards should keep whole length of block
        ISOException.throwIt(MathStatus.SW_EC_POINT_UNEXPECTED_AGREEMENT_LENGTH);
      }
    }

    tmpMod.fromByteArray(tmpBuffer, (short) 0, resources.maxExponentLength);

    if (MathSupport.getInstance().rsaExtraModulo) {
      tmpMod.mod(mod);
    }

    setSize(mod.length());
    copy(tmpMod);
  }

  /**
   * Computes modular inversion. The result is stored into this.
   */
  public void modInv(BigNat mod) {
    BigNat tmp = resources.bigNatB;

    tmp.clone(mod);
    tmp.decrement();
    tmp.decrement();

    modExp(tmp, mod);
  }

  /**
   * Multiplication of this and other modulo mod. The result is stored to this.
   */
  public void modMult(BigNat other, BigNat mod) {
    BigNat tmp = resources.bigNatD;
    BigNat result = resources.bigNatE;

    if (MathSupport.getInstance().rsaCheckOne && equals((byte) 1)) {
      copy(other);

      return;
    }

    if (!MathSupport.getInstance().rsaSquaring || MathSupport.getInstance().rsaExtraModulo) {
      result.clone(this);
      result.mult(other);
      result.mod(mod);
    } else {
      result.setSize((short) (mod.length() + 1));
      result.copy(this);
      result.add(other);

      short carry = (byte) 0;

      if (result.isOdd()) {
        if (result.isLesser(mod)) {
          carry = result.add(mod);
        } else {
          result.subtract(mod);
        }
      }

      result.shiftRight((short) 1, carry);
      result.resize(mod.length());

      tmp.clone(result);
      tmp.modSub(other, mod);

      result.modSq(mod);
      tmp.modSq(mod);

      result.modSub(tmp, mod);
    }

    setSize(mod.length());
    copy(result);
  }

  /**
   * Computes modulo square of this BigNat.
   */
  public void modSq(BigNat mod) {
    if (MathSupport.getInstance().rsaSquaring) {
      if (resources.fixedModulus != null && resources.fixedModulus == mod) {
        modSqFixed();
      } else {
        modExp(resources.two, mod);
      }
    } else {
      modMult(this, mod);
    }
  }

  /**
   * Computes square root of provided BigNat which MUST be prime using Tonelli Shanks Algorithm. The result (one of
   * the two roots) is stored to this.
   */
  public void modSqrt(BigNat p) {
    BigNat exp = resources.bigNatG;
    BigNat p1 = resources.bigNatB;
    BigNat q = resources.bigNatC;
    BigNat tmp = resources.bigNatD;
    BigNat z = resources.bigNatA;
    BigNat t = resources.bigNatB;
    BigNat b = resources.bigNatC;

    // 1. Find Q and S such that p - 1 = Q * 2^S and Q is odd
    p1.clone(p);
    p1.decrement();

    q.clone(p1);

    short s = 0;

    while (!q.isOdd()) {
      ++s;
      q.shiftRight((short) 1);
    }

    // 2. Find the first quadratic non-residue z by brute-force search
    exp.clone(p1);
    exp.shiftRight((short) 1);

    z.setSize(p.length());
    z.setValue((byte) 1);
    tmp.setSize(p.length());
    tmp.setValue((byte) 1);

    while (!tmp.equals(p1)) {
      z.increment();
      tmp.copy(z);
      tmp.modExp(exp, p); // Euler's criterion
    }

    // 3. Compute the first candidate
    exp.clone(q);
    exp.increment();
    exp.shiftRight((short) 1);

    t.clone(this);
    t.modExp(q, p);

    if (t.equals((byte) 0)) {
      zero();

      return;
    }

    mod(p);
    modExp(exp, p);

    if (t.equals((byte) 1)) {
      return;
    }

    // 4. Search for further candidates
    z.modExp(q, p);

    while (true) {
      tmp.clone(t);
      short i = 0;

      do {
        tmp.modSq(p);
        ++i;
      } while (!tmp.equals((byte) 1));

      b.clone(z);
      s -= i;
      --s;

      tmp.setSize((short) 1);
      tmp.setValue((byte) 1);

      while (s != 0) {
        tmp.shiftLeft((short) 1);
        --s;
      }

      b.modExp(tmp, p);
      s = i;
      z.clone(b);
      z.modSq(p);
      t.modMult(z, p);
      modMult(b, p);

      if (t.equals((byte) 0)) {
        zero();
        break;
      }

      if (t.equals((byte) 1)) {
        break;
      }
    }
  }
}
