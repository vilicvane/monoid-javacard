// Derived from JCEd25519 / JCMathLib 2.1-rc.1 (MIT).
// Copyright (c) 2022 Antonin Dufka; JCMathLib authors Vasilios Mavroudis, Petr Svenda, Antonin Dufka.
// Source, changes and licenses: third-party/jced25519/PROVENANCE.md.
package monoid;

import javacard.framework.JCSystem;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

public final class ECCurve {

  public final short keyBitLength;
  public final short pointSize;
  public final short coordinateSize;
  public MathResources resources;

  public byte[] p;
  public byte[] a;
  public byte[] b;
  public byte[] g;
  public byte[] r;
  public short k;
  public BigNat pValue;
  public BigNat aValue;
  public BigNat bValue;
  public BigNat rValue;

  public KeyPair sharedKeyPair;
  public ECPrivateKey sharedPrivateKey;
  public ECPublicKey sharedPublicKey;

  /**
   * Creates new curve object from provided parameters. Parameters are not copied, the
   * arrays must not be changed.
   *
   * @param p array with p
   * @param a array with a
   * @param b array with b
   * @param g array with base point g
   * @param r array with r
   */
  public ECCurve(
    byte[] p,
    byte[] a,
    byte[] b,
    byte[] g,
    byte[] r,
    short k,
    MathResources resources
  ) {
    short bits = (short) (p.length * 8);

    if (MathSupport.getInstance().ecPreciseBitLength) {
      for (short i = 0; i < (short) p.length; ++i) {
        bits -= 8;

        if (p[i] != (byte) 0x00) {
          short tmp = (short) (p[i] & 0xFF);

          while (tmp != (short) 0x00) {
            tmp >>= (short) 1;
            ++bits;
          }

          break;
        }
      }
    }

    keyBitLength = bits;
    pointSize = (short) g.length;
    coordinateSize = (short) ((short) (g.length - 1) / 2);

    this.p = p;
    this.a = a;
    this.b = b;
    this.g = g;
    this.r = r;
    this.k = k;
    this.resources = resources;

    pValue = new BigNat(coordinateSize, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, resources);
    pValue.fromByteArray(p, (short) 0, (short) p.length);
    aValue = new BigNat(coordinateSize, JCSystem.MEMORY_TYPE_PERSISTENT, resources);
    aValue.fromByteArray(a, (short) 0, (short) a.length);
    bValue = new BigNat(coordinateSize, JCSystem.MEMORY_TYPE_PERSISTENT, resources);
    bValue.fromByteArray(b, (short) 0, (short) b.length);
    rValue = new BigNat(coordinateSize, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, resources);
    rValue.fromByteArray(r, (short) 0, (short) r.length);

    sharedKeyPair = newKeyPair(null);
    sharedPrivateKey = (ECPrivateKey) sharedKeyPair.getPrivate();
    sharedPublicKey = (ECPublicKey) sharedKeyPair.getPublic();
  }

  /**
   * Refresh critical information stored in RAM for performance reasons after a card reset (RAM was cleared).
   */
  public void updateAfterReset() {
    pValue.fromByteArray(p, (short) 0, (short) p.length);
    // aValue and bValue are persistent constants; avoid rewriting them for every signature.
    rValue.fromByteArray(r, (short) 0, (short) r.length);
    // Monoid keeps the multiplication scalar in a transient native key.
    sharedPrivateKey.setFieldFP(p, (short) 0, (short) p.length);
    sharedPrivateKey.setA(a, (short) 0, (short) a.length);
    sharedPrivateKey.setB(b, (short) 0, (short) b.length);
    sharedPrivateKey.setG(g, (short) 0, (short) g.length);
    sharedPrivateKey.setR(r, (short) 0, (short) r.length);
    sharedPrivateKey.setK(MathSupport.getInstance().ecSetCofactor ? k : (short) 1);
  }

  /**
   * Creates a new keyPair based on this curve parameters. KeyPair object is reused if provided. Fresh keyPair value is generated.
   * @param keyPair existing KeyPair object which is reused if required. If null, new KeyPair is allocated
   * @return new or existing object with fresh key pair value
   */
  KeyPair newKeyPair(KeyPair keyPair) {
    ECPublicKey pubKey;
    ECPrivateKey privKey;

    if (keyPair == null) {
      pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, keyBitLength, false);
      privKey = (ECPrivateKey) KeyBuilder.buildKey(
        KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
        JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT,
        keyBitLength,
        false
      );
      keyPair = new KeyPair(pubKey, privKey);
    } else {
      pubKey = (ECPublicKey) keyPair.getPublic();
      privKey = (ECPrivateKey) keyPair.getPrivate();
    }

    privKey.setFieldFP(p, (short) 0, (short) p.length);
    privKey.setA(a, (short) 0, (short) a.length);
    privKey.setB(b, (short) 0, (short) b.length);
    privKey.setG(g, (short) 0, (short) g.length);
    privKey.setR(r, (short) 0, (short) r.length);
    privKey.setK(MathSupport.getInstance().ecSetCofactor ? k : (short) 1);

    pubKey.setFieldFP(p, (short) 0, (short) p.length);
    pubKey.setA(a, (short) 0, (short) a.length);
    pubKey.setB(b, (short) 0, (short) b.length);
    pubKey.setG(g, (short) 0, (short) g.length);
    pubKey.setR(r, (short) 0, (short) r.length);
    pubKey.setK(MathSupport.getInstance().ecSetCofactor ? k : (short) 1);

    if (MathSupport.getInstance().ecKeyGeneration) {
      keyPair.genKeyPair();
    } else {
      privKey.setS(MathResources.CONST_ONE, (short) 0, (short) 1);
      pubKey.setW(g, (short) 0, (short) g.length);
    }

    return keyPair;
  }
}
