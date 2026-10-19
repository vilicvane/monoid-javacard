package monoid;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public final class CommandCreateBundle extends Command implements CBORResponse {

  private static final short PUBLIC_KEY_LENGTH = 65;
  private static final short CHUNK_LENGTH = 256;

  private final Object[] references = JCSystem.makeTransientObjectArray(
    (short) 2,
    JCSystem.CLEAR_ON_DESELECT
  );
  private final short[] state = JCSystem.makeTransientShortArray(
    (short) 5,
    JCSystem.CLEAR_ON_DESELECT
  );

  @Override
  protected void run() {
    requireAuth(AUTH_SAFE);

    reader.map();
    short count = reader.requireKey(Text.publicKeys).array();

    if (count < 2 || count > CBORApduReader.MAX_LENGTH / (PUBLIC_KEY_LENGTH + 2)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Reserve the response window before creating and publishing the Bundle.
    // Each unit contains at most a packet's map header and one data chunk.
    writer.start(
      this,
      (short) (CHUNK_LENGTH +
        1 +
        1 +
        Text.publicKey.length +
        2 +
        PUBLIC_KEY_LENGTH +
        1 +
        Text.data.length +
        3)
    );

    byte[] publicKeys = Utils.makePrivateByteArray((short) (count * PUBLIC_KEY_LENGTH));

    for (short index = 0; index < count; index++) {
      short offset = reader.getOffset();

      if (reader.bytesLength() != PUBLIC_KEY_LENGTH) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      reader.setOffset(offset);
      reader.bytes(publicKeys, (short) (index * PUBLIC_KEY_LENGTH));
    }

    byte[] ownPublicKey = MonoidApplet.safe.getPublicKey();
    SafeDataSource packets = MonoidApplet.safe.createBundle(publicKeys);
    short packetLength = (short) (packets.getLength() / (short) (count - 1));
    short ownOffset = 0;

    while (!Utils.isEqual(ownPublicKey, publicKeys, ownOffset, PUBLIC_KEY_LENGTH)) {
      ownOffset += PUBLIC_KEY_LENGTH;
    }

    references[0] = publicKeys;
    references[1] = packets;
    state[0] = 0;
    state[1] = 0;
    state[2] = packetLength;
    state[3] = ownOffset;
    state[4] = 0;

    writer.map((short) 2);
    {
      writer.text(Text.bundle);
      writer.bytes(MonoidApplet.safe.getBundle());

      writer.text(Text.packets);
      writer.array((short) (count - 1));
    }
  }

  @Override
  public boolean writeNext(CBORWriter writer) {
    byte[] publicKeys = (byte[]) references[0];

    if (state[0] == state[3]) {
      state[0] += PUBLIC_KEY_LENGTH;
    }

    if (state[0] >= publicKeys.length) {
      return false;
    }

    if (state[1] == 0) {
      writer.map((short) 2);
      writer.text(Text.publicKey);
      writer.bytes(publicKeys, state[0], PUBLIC_KEY_LENGTH);
      writer.text(Text.data);
      writer.bytesLength(state[2]);
    }

    byte[] buffer = APDU.getCurrentAPDUBuffer();
    short length = Utils.min(
      (short) (state[2] - state[1]),
      Utils.min(CHUNK_LENGTH, (short) buffer.length)
    );
    ((SafeDataSource) references[1]).read(state[4], buffer, (short) 0, length);
    writer.rawBytes(buffer, (short) 0, length);
    state[1] += length;
    state[4] += length;

    if (state[1] == state[2]) {
      state[0] += PUBLIC_KEY_LENGTH;
      state[1] = 0;
    }

    return state[0] < publicKeys.length;
  }

  @Override
  public void reset() {
    references[0] = null;
    references[1] = null;
    for (short index = 0; index < state.length; index++) {
      state[index] = 0;
    }
  }
}
