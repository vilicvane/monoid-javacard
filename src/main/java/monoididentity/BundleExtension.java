package monoididentity;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/** Bundle possession and an individual Identity signature jointly authorize admission. */
final class BundleExtension {

  private static final byte VERSION = 1;

  private static final short PUBLIC_KEY_LENGTH = CommunicationCipher.PUBLIC_KEY_LENGTH;
  private static final short HASH_LENGTH = MessageDigest.LENGTH_SHA_256;

  private static final short MIN_SIGNATURE_LENGTH = 8;
  private static final short MAX_SIGNATURE_LENGTH = 72;

  private static final short HASH_OFFSET = 1;
  private static final short INITIATOR_OFFSET = HASH_OFFSET + HASH_LENGTH;
  private static final short TARGET_OFFSET = INITIATOR_OFFSET + PUBLIC_KEY_LENGTH;
  private static final short MAC_OFFSET = TARGET_OFFSET + PUBLIC_KEY_LENGTH;
  private static final short SIGNATURE_LENGTH_OFFSET = MAC_OFFSET + HASH_LENGTH;
  private static final short SIGNATURE_OFFSET = SIGNATURE_LENGTH_OFFSET + 1;

  // @formatter:off
  private static final byte[] CONTEXT = {'M','o','n','o','i','d',' ','B','u','n','d','l','e',' ','E','x','t','e','n','s','i','o','n'};
  // @formatter:on

  private final KeyPair identity;
  private final ECPublicKey initiatorKey;

  private final MessageDigest digest;
  private final Signature signature;

  private final byte[] hmacBlock;

  BundleExtension(KeyPair identity, byte[] hmacBlock) {
    this.identity = identity;

    this.hmacBlock = hmacBlock;

    initiatorKey = (ECPublicKey) KeyBuilder.buildKey(
      KeyBuilder.ALG_TYPE_EC_FP_PUBLIC,
      JCSystem.MEMORY_TYPE_PERSISTENT,
      KeyBuilder.LENGTH_EC_FP_256,
      false
    );

    LibSECP256r1.initialize(initiatorKey);

    // Identity executes through a Shareable while Monoid is selected.
    digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);

    signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, true);
  }

  byte[] extend(Bundle bundle, byte[] publicKey) {
    bundle.assertPeerExtension();

    CommunicationCipher.assertPublicKey(publicKey, (short) 0, (short) publicKey.length);

    byte[] request = new byte[SIGNATURE_OFFSET + MAX_SIGNATURE_LENGTH];

    request[0] = VERSION;
    Util.arrayCopyNonAtomic(bundle.hash, (short) 0, request, HASH_OFFSET, HASH_LENGTH);
    ((ECPublicKey) identity.getPublic()).getW(request, INITIATOR_OFFSET);
    Util.arrayCopyNonAtomic(publicKey, (short) 0, request, TARGET_OFFSET, PUBLIC_KEY_LENGTH);

    computeMAC(bundle, request, request, MAC_OFFSET);

    signature.init(identity.getPrivate(), Signature.MODE_SIGN);
    signature.update(CONTEXT, (short) 0, (short) CONTEXT.length);

    short length = signature.sign(
      request,
      (short) 0,
      SIGNATURE_LENGTH_OFFSET,
      request,
      SIGNATURE_OFFSET
    );

    request[SIGNATURE_LENGTH_OFFSET] = (byte) length;

    byte[] result = new byte[(short) (SIGNATURE_OFFSET + length)];
    Util.arrayCopyNonAtomic(request, (short) 0, result, (short) 0, (short) result.length);

    return result;
  }

  byte[] requireRecipientPublicKey(Bundle bundle, byte[] request) {
    bundle.assertPeerExtension();

    if (
      request.length < SIGNATURE_OFFSET + MIN_SIGNATURE_LENGTH ||
      request.length > SIGNATURE_OFFSET + MAX_SIGNATURE_LENGTH ||
      request[0] != VERSION ||
      (short) (request[SIGNATURE_LENGTH_OFFSET] & 0xFF) !=
      (short) (request.length - SIGNATURE_OFFSET)
    ) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    byte[] hash = new byte[HASH_LENGTH];
    Util.arrayCopyNonAtomic(request, HASH_OFFSET, hash, (short) 0, (short) hash.length);

    if (LibSecurity.check(bundle.hash, hash, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] ownPublicKey = new byte[PUBLIC_KEY_LENGTH];
    byte[] initiator = new byte[PUBLIC_KEY_LENGTH];

    ((ECPublicKey) identity.getPublic()).getW(ownPublicKey, (short) 0);
    Util.arrayCopyNonAtomic(request, INITIATOR_OFFSET, initiator, (short) 0, PUBLIC_KEY_LENGTH);

    if (LibSecurity.check(ownPublicKey, initiator, Constants.SAFE_TRUE) != Constants.SAFE_FALSE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] expectedMAC = new byte[HASH_LENGTH];
    byte[] actualMAC = new byte[HASH_LENGTH];

    computeMAC(bundle, request, expectedMAC, (short) 0);
    Util.arrayCopyNonAtomic(request, MAC_OFFSET, actualMAC, (short) 0, (short) actualMAC.length);

    if (LibSecurity.check(expectedMAC, actualMAC, Constants.SAFE_FALSE) != Constants.SAFE_TRUE) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    CommunicationCipher.assertPublicKey(initiator, (short) 0, (short) initiator.length);
    initiatorKey.setW(initiator, (short) 0, (short) initiator.length);

    signature.init(initiatorKey, Signature.MODE_VERIFY);
    signature.update(CONTEXT, (short) 0, (short) CONTEXT.length);

    if (
      !signature.verify(
        request,
        (short) 0,
        SIGNATURE_LENGTH_OFFSET,
        request,
        SIGNATURE_OFFSET,
        (short) (request.length - SIGNATURE_OFFSET)
      )
    ) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    byte[] publicKey = new byte[PUBLIC_KEY_LENGTH];
    Util.arrayCopyNonAtomic(request, TARGET_OFFSET, publicKey, (short) 0, (short) publicKey.length);

    CommunicationCipher.assertPublicKey(publicKey, (short) 0, (short) publicKey.length);

    return publicKey;
  }

  private void computeMAC(Bundle bundle, byte[] request, byte[] output, short offset) {
    LibHMACSha256.begin(digest, hmacBlock, bundle.key, (short) 0, (short) bundle.key.length);

    digest.update(CONTEXT, (short) 0, (short) CONTEXT.length);
    digest.doFinal(request, (short) 0, MAC_OFFSET, output, offset);

    LibHMACSha256.finish(digest, hmacBlock, output, offset);
  }
}
