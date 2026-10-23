package monoidsecuritykey;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import monoidlib.CBORMap;
import monoidlib.CBORReader;
import monoidlib.CBORWriter;

final class CommandClientPIN extends Command {

  private static final short[] FIELDS = { 1, 2, 3, 4, 5, 6 };

  private final CBORMap fields = new CBORMap(FIELDS);
  private final CBORMap keyAgreementFields = new CBORMap(LibCOSE.KEY_AGREEMENT_FIELDS);

  @Override
  void execute(CBORReader reader, CBORWriter writer) {
    fields.read(reader);
    assertEmpty(reader);
    if (fields.requireKey((short) 1).integer() != 1) {
      ISOException.throwIt(CTAP.INVALID_PARAMETER);
    }
    short subCommand = fields.requireKey((short) 2).integer();
    ClientPIN pin = authenticator.pin;
    switch (subCommand) {
      case 1:
        writer.map((short) 1);
        writer.integer((short) 3);
        writer.integer(pin.getRetries());
        return;
      case 2: {
        byte[] buffer = APDU.getCurrentAPDUBuffer();
        short pointOffset = (short) (buffer.length - 65);
        pin.getKeyAgreement(buffer, pointOffset);
        writer.map((short) 1);
        writer.integer((short) 1);
        LibCOSE.writePublicKey(writer, buffer, pointOffset, (short) -25);
        return;
      }
      case 3:
        pin.setPIN(
          LibCOSE.readKeyAgreement(fields.requireKey((short) 3)),
          fields.requireKey((short) 4).bytes((short) 16),
          fields.requireKey((short) 5).bytes()
        );
        return;
      case 4:
        pin.changePIN(
          LibCOSE.readKeyAgreement(fields.requireKey((short) 3)),
          fields.requireKey((short) 4).bytes((short) 16),
          fields.requireKey((short) 5).bytes(),
          fields.requireKey((short) 6).bytes((short) 16)
        );
        return;
      case 5: {
        // The response writer uses the first 64 APDU bytes. Keep its input in the tail.
        byte[] buffer = APDU.getCurrentAPDUBuffer();
        short pointOffset = (short) (buffer.length - 65);
        short hashOffset = (short) (pointOffset - 16);
        short tokenOffset = (short) (buffer.length - 32);
        LibCOSE.readKeyAgreement(
          fields.requireKey((short) 3),
          keyAgreementFields,
          buffer,
          pointOffset
        );
        fields.requireKey((short) 6).bytes(buffer, hashOffset, (short) 16);
        pin.getPINToken(buffer, pointOffset, buffer, hashOffset, buffer, tokenOffset);
        writer.map((short) 1);
        writer.integer((short) 2);
        writer.bytes(buffer, tokenOffset, (short) 32);
        return;
      }
      default:
        ISOException.throwIt(CTAP.INVALID_PARAMETER);
    }
  }
}
