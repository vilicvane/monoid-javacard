package monoididentity;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.RandomData;

/** A Bundle root and its enrollment snapshot, published together by its Identity. */
final class Bundle {

  private static final byte VERSION = 1;
  private static final short PUBLIC_KEYS_OFFSET = 3;
  private static final short PUBLIC_KEY_LENGTH = CommunicationCipher.PUBLIC_KEY_LENGTH;
  private static final short KEY_LENGTH = CommunicationCipher.KEY_LENGTH;

  // @formatter:off
  private static final byte[] CONTEXT = {'M','o','n','o','i','d',' ','B','u','n','d','l','e',' ','E','n','r','o','l','l','m','e','n','t'};
  // @formatter:on

  final byte[] key;
  final byte[] hash;
  private final byte[] publicKeys;

  private Bundle(byte[] key, byte[] publicKeys, CommunicationCipher cipher) {
    this.key = new byte[KEY_LENGTH];
    Util.arrayCopyNonAtomic(key, (short) 0, this.key, (short) 0, KEY_LENGTH);
    this.publicKeys = publicKeys;
    hash = cipher.hash(key);
  }

  static Bundle create(byte[] publicKeys, byte[] ownPublicKey, CommunicationCipher cipher) {
    short length = (short) (publicKeys.length + PUBLIC_KEY_LENGTH);
    assertPublicKeysLength(length);

    byte[] members = new byte[length];
    byte[] member = new byte[PUBLIC_KEY_LENGTH];

    Util.arrayCopyNonAtomic(publicKeys, (short) 0, members, (short) 0, (short) publicKeys.length);
    Util.arrayCopyNonAtomic(
      ownPublicKey,
      (short) 0,
      members,
      (short) publicKeys.length,
      PUBLIC_KEY_LENGTH
    );

    for (short offset = 0; offset < members.length; offset += PUBLIC_KEY_LENGTH) {
      CommunicationCipher.assertPublicKey(members, offset, PUBLIC_KEY_LENGTH);
      Util.arrayCopyNonAtomic(members, offset, member, (short) 0, PUBLIC_KEY_LENGTH);
      short position = offset;

      while (
        position > 0 &&
        CommunicationCipher.compareUnsigned(
          members,
          (short) (position - PUBLIC_KEY_LENGTH),
          member,
          (short) 0,
          PUBLIC_KEY_LENGTH
        ) >
        0
      ) {
        Util.arrayCopyNonAtomic(
          members,
          (short) (position - PUBLIC_KEY_LENGTH),
          members,
          position,
          PUBLIC_KEY_LENGTH
        );
        position -= PUBLIC_KEY_LENGTH;
      }

      Util.arrayCopyNonAtomic(member, (short) 0, members, position, PUBLIC_KEY_LENGTH);
    }

    assertCanonicalMembers(members);

    byte[] key = new byte[KEY_LENGTH];
    RandomData.getInstance(RandomData.ALG_KEYGENERATION).nextBytes(key, (short) 0, KEY_LENGTH);

    return new Bundle(key, members, cipher);
  }

  static Bundle decrypt(
    byte[] senderPublicKey,
    byte[] ownPublicKey,
    byte[] data,
    CommunicationCipher cipher
  ) {
    if (
      data.length <
        PUBLIC_KEYS_OFFSET + PUBLIC_KEY_LENGTH * 2 + CommunicationCipher.ENCRYPTED_KEY_LENGTH ||
      data[0] != VERSION
    ) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    short length = (short) (data.length -
      PUBLIC_KEYS_OFFSET -
      CommunicationCipher.ENCRYPTED_KEY_LENGTH);
    assertPublicKeysLength(length);

    if (Util.getShort(data, (short) 1) != (short) (length / PUBLIC_KEY_LENGTH)) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    byte[] members = new byte[length];
    Util.arrayCopyNonAtomic(data, PUBLIC_KEYS_OFFSET, members, (short) 0, length);
    assertCanonicalMembers(members);
    assertMember(members, ownPublicKey);
    assertMember(members, senderPublicKey);

    byte[] encryptedKey = CommunicationData.makePrivateByteArray(
      CommunicationCipher.ENCRYPTED_KEY_LENGTH
    );
    Util.arrayCopyNonAtomic(
      data,
      (short) (PUBLIC_KEYS_OFFSET + length),
      encryptedKey,
      (short) 0,
      CommunicationCipher.ENCRYPTED_KEY_LENGTH
    );
    byte[] key = cipher.decrypt(senderPublicKey, context(members, cipher), encryptedKey);

    return new Bundle(key, members, cipher);
  }

  byte[] encryptPackets(byte[] recipients, CommunicationCipher cipher) {
    short count = (short) (publicKeys.length / PUBLIC_KEY_LENGTH - 1);
    short packetLength = packetLength(publicKeys);

    if (packetLength > (short) (0x7FFF / count)) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    byte[] data = new byte[(short) (packetLength * count)];
    byte[] recipient = new byte[PUBLIC_KEY_LENGTH];
    byte[] context = context(publicKeys, cipher);
    short offset = 0;

    for (
      short memberOffset = 0;
      memberOffset < recipients.length;
      memberOffset += PUBLIC_KEY_LENGTH
    ) {
      Util.arrayCopyNonAtomic(recipients, memberOffset, recipient, (short) 0, PUBLIC_KEY_LENGTH);
      encrypt(recipient, publicKeys, cipher, context, data, offset);
      offset += packetLength;
    }

    return data;
  }

  byte[] encryptFor(byte[] recipientPublicKey, byte[] ownPublicKey, CommunicationCipher cipher) {
    assertMember(publicKeys, ownPublicKey);

    byte[] members = publicKeys;

    if (!contains(recipientPublicKey)) {
      short length = (short) (publicKeys.length + PUBLIC_KEY_LENGTH);
      assertPublicKeysLength(length);

      members = new byte[length];
      short position = 0;

      while (
        position < publicKeys.length &&
        CommunicationCipher.compareUnsigned(
          publicKeys,
          position,
          recipientPublicKey,
          (short) 0,
          PUBLIC_KEY_LENGTH
        ) <
        0
      ) {
        position += PUBLIC_KEY_LENGTH;
      }

      Util.arrayCopyNonAtomic(publicKeys, (short) 0, members, (short) 0, position);
      Util.arrayCopyNonAtomic(recipientPublicKey, (short) 0, members, position, PUBLIC_KEY_LENGTH);
      Util.arrayCopyNonAtomic(
        publicKeys,
        position,
        members,
        (short) (position + PUBLIC_KEY_LENGTH),
        (short) (publicKeys.length - position)
      );
    }

    byte[] data = new byte[packetLength(members)];

    encrypt(recipientPublicKey, members, cipher, context(members, cipher), data, (short) 0);

    return data;
  }

  private static short packetLength(byte[] publicKeys) {
    return (short) (PUBLIC_KEYS_OFFSET +
      publicKeys.length +
      CommunicationCipher.ENCRYPTED_KEY_LENGTH);
  }

  private void encrypt(
    byte[] recipientPublicKey,
    byte[] publicKeys,
    CommunicationCipher cipher,
    byte[] context,
    byte[] data,
    short offset
  ) {
    data[offset] = VERSION;
    Util.setShort(data, (short) (offset + 1), (short) (publicKeys.length / PUBLIC_KEY_LENGTH));
    Util.arrayCopyNonAtomic(
      publicKeys,
      (short) 0,
      data,
      (short) (offset + PUBLIC_KEYS_OFFSET),
      (short) publicKeys.length
    );
    cipher.encrypt(
      recipientPublicKey,
      context,
      key,
      data,
      (short) (offset + PUBLIC_KEYS_OFFSET + publicKeys.length)
    );
  }

  boolean matches(Bundle other) {
    return LibSecurity.check(key, other.key, Constants.SAFE_FALSE) == Constants.SAFE_TRUE;
  }

  boolean contains(byte[] publicKey) {
    if (publicKey != null && publicKey.length == PUBLIC_KEY_LENGTH) {
      for (short offset = 0; offset < publicKeys.length; offset += PUBLIC_KEY_LENGTH) {
        if (Util.arrayCompare(publicKeys, offset, publicKey, (short) 0, PUBLIC_KEY_LENGTH) == 0) {
          return true;
        }
      }
    }

    return false;
  }

  private static byte[] context(byte[] publicKeys, CommunicationCipher cipher) {
    byte[] context = new byte[(short) (CONTEXT.length + 1 + publicKeys.length)];
    Util.arrayCopyNonAtomic(CONTEXT, (short) 0, context, (short) 0, (short) CONTEXT.length);
    context[CONTEXT.length] = VERSION;
    Util.arrayCopyNonAtomic(
      publicKeys,
      (short) 0,
      context,
      (short) (CONTEXT.length + 1),
      (short) publicKeys.length
    );

    return cipher.hash(context);
  }

  private static void assertPublicKeysLength(short length) {
    if (
      length < PUBLIC_KEY_LENGTH * 2 ||
      length % PUBLIC_KEY_LENGTH != 0 ||
      length > 0x7FFF - PUBLIC_KEYS_OFFSET - CommunicationCipher.ENCRYPTED_KEY_LENGTH
    ) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
  }

  private static void assertCanonicalMembers(byte[] publicKeys) {
    for (short offset = 0; offset < publicKeys.length; offset += PUBLIC_KEY_LENGTH) {
      CommunicationCipher.assertPublicKey(publicKeys, offset, PUBLIC_KEY_LENGTH);

      if (
        offset > 0 &&
        CommunicationCipher.compareUnsigned(
          publicKeys,
          (short) (offset - PUBLIC_KEY_LENGTH),
          publicKeys,
          offset,
          PUBLIC_KEY_LENGTH
        ) >=
        0
      ) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
    }
  }

  private static void assertMember(byte[] publicKeys, byte[] publicKey) {
    if (publicKey != null && publicKey.length == PUBLIC_KEY_LENGTH) {
      for (short offset = 0; offset < publicKeys.length; offset += PUBLIC_KEY_LENGTH) {
        if (Util.arrayCompare(publicKeys, offset, publicKey, (short) 0, PUBLIC_KEY_LENGTH) == 0) {
          return;
        }
      }
    }

    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
  }
}
