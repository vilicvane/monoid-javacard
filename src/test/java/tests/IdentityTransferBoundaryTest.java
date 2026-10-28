package tests;

import static tests.AppletTest.aidBytes;
import static tests.MonoidItemTransferTest.assertError;
import static tests.MonoidItemTransferTest.customIndex;
import static tests.MonoidItemTransferTest.fields;
import static tests.MonoidItemTransferTest.sequence;

import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import monoididentity.CommunicationDataShareable;
import monoididentity.IdentityShareable;
import monoidlib.CBORBufferReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tests.MonoidItemTransferTest.Card;
import tests.MonoidItemTransferTest.Result;

/** SIO and APDU boundary checks; the simulator does not establish physical GP installation policy. */
public class IdentityTransferBoundaryTest {

  private static final AID IDENTITY_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_IDENTITY_AID}}"
    "f06d6f6e6f69640001"
  );
  private static final AID MONOID_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_AID}}"
    "f06d6f6e6f69640201"
  );
  private static final AID CLIENT_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_NAMESPACE}}7f31"
    "f06d6f6e6f69647f31"
  );
  private static final AID RECOVERY_MODULE_AID = AIDUtil.create(
    // @inplate-line "{{hex MONOID_NAMESPACE}}7f32"
    "f06d6f6e6f69647f32"
  );

  @Test
  public void exportedRecordsBelongToTheCallerAIDRatherThanTheOldMonoidInstallation() {
    // Monoid statics are JVM-wide, so its instances run sequentially across the two cards.
    try (Card source = new Card(false); Card target = new Card(false)) {
      byte[] sourcePublicKey = source.bootstrapPublicKey();
      byte[] targetPublicKey = target.bootstrapPublicKey();
      byte[] index = customIndex(301);
      byte[] key = sequence(12);
      String alias = "shared secret";
      byte[] aliasBytes = alias.getBytes(StandardCharsets.UTF_8);
      byte[] secret = sequence(32);

      source.installMonoid();
      source.create(index, key, alias, secret, true);
      assertError(source.transmit(0x32, fields("index", index)), "ACCESS_DENIED");
      assertError(source.transmit(0x36, fields("index", index)), "ACCESS_DENIED");
      source.reset();
      assertError(source.transmit(0x36, fields("index", index)), "UNAUTHORIZED");
      source.authenticate(true);
      Result created = source.success(0x23, fields("publicKeys", new byte[][] { targetPublicKey }));
      byte[] bundle = created.bytes("bundle");
      CBORBufferReader packets = created.reader();
      Assertions.assertEquals(1, packets.requireKey(ascii("data")).array());
      Assertions.assertTrue(packets.index((short) 0));
      byte[] enrollment = packets.bytes().clone();
      byte[] exported = source.success(0x36, fields("index", index)).bytes("data");
      Assertions.assertEquals(2, exported[0]);
      Assertions.assertArrayEquals(bundle, Arrays.copyOfRange(exported, 1, 33));
      source.uninstallMonoid();

      target.installMonoid();
      target.authenticate(true);
      Assertions.assertArrayEquals(
        bundle,
        target
          .success(0x24, fields("publicKey", sourcePublicKey, "data", enrollment))
          .bytes("bundle")
      );
      target.reset();
      target.uninstallMonoid();

      installClient(target, CLIENT_AID, CLIENT_AID);
      installClient(target, RECOVERY_MODULE_AID, MONOID_AID);

      try {
        byte[] request = payload(index, key, aliasBytes, exported);
        Assertions.assertEquals(0x6982, transmit(target, CLIENT_AID, 2, request).getSW());
        Assertions.assertEquals(0x6982, transmit(target, MONOID_AID, 2, request).getSW());
        authenticate(target, MONOID_AID);
        Assertions.assertArrayEquals(plaintext(secret), success(target, MONOID_AID, 2, request));
        Assertions.assertEquals(0x6982, transmit(target, CLIENT_AID, 2, request).getSW());
        authenticate(target, CLIENT_AID);
        Assertions.assertEquals(0x6982, transmit(target, CLIENT_AID, 2, request).getSW());

        // Ordinary applets share the Bundle transport, but each complete AID has its own domain.
        installClient(source, CLIENT_AID, CLIENT_AID);
        try {
          authenticate(source, CLIENT_AID);
          byte[] clientData = sequence(48);
          byte[] clientEnvelope = success(
            source,
            CLIENT_AID,
            1,
            payload(index, key, aliasBytes, clientData)
          );
          Assertions.assertEquals(2, clientEnvelope[0]);
          Assertions.assertArrayEquals(bundle, Arrays.copyOfRange(clientEnvelope, 1, 33));
          byte[] clientRequest = payload(index, key, aliasBytes, clientEnvelope);
          Assertions.assertArrayEquals(
            plaintext(clientData),
            success(target, CLIENT_AID, 2, clientRequest)
          );
          Assertions.assertEquals(0x6982, transmit(target, MONOID_AID, 2, clientRequest).getSW());
          authenticate(target, MONOID_AID);
          Assertions.assertEquals(0x6982, transmit(target, MONOID_AID, 2, clientRequest).getSW());
          Assertions.assertArrayEquals(plaintext(secret), success(target, MONOID_AID, 2, request));
        } finally {
          source.simulator.deleteApplet(CLIENT_AID);
        }
      } finally {
        target.simulator.deleteApplet(MONOID_AID);
        target.simulator.deleteApplet(CLIENT_AID);
      }
    }
  }

  private static void installClient(Card card, AID module, AID instance) {
    byte[] aid = aidBytes(instance);
    // Load a distinct module, then register the desired instance AID through install parameters.
    card.simulator.installApplet(module, TransferApplet.class, aid, (short) 0, (byte) aid.length);
    Assertions.assertTrue(card.simulator.selectApplet(instance));
  }

  private static ResponseAPDU transmit(Card card, AID caller, int instruction, byte[] request) {
    Assertions.assertTrue(card.simulator.selectApplet(caller));
    return card.simulator.transmitCommand(new CommandAPDU(0, instruction, 0, 0, request, 256));
  }

  private static byte[] success(Card card, AID caller, int instruction, byte[] request) {
    ResponseAPDU response = transmit(card, caller, instruction, request);
    Assertions.assertEquals(0x9000, response.getSW());
    return response.getData();
  }

  private static void authenticate(Card card, AID caller) {
    success(card, caller, 3, ascii("888888"));
  }

  private static byte[] payload(byte[] index, byte[] key, byte[] alias, byte[] data) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    output.write(index, 0, index.length);
    output.write(key.length);
    output.write(key, 0, key.length);
    output.write(alias.length);
    output.write(alias, 0, alias.length);
    output.write(data, 0, data.length);
    return output.toByteArray();
  }

  private static byte[] plaintext(byte[] data) {
    byte[] plaintext = new byte[data.length + 2];
    plaintext[0] = 0x5A;
    plaintext[1] = (byte) 0xFE;
    System.arraycopy(data, 0, plaintext, 2, data.length);
    return plaintext;
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  /** A test-only applet exposing its own transfer domain and explicit Identity PIN verification. */
  public static class TransferApplet extends Applet {

    public static void install(byte[] buffer, short offset, byte length) {
      new TransferApplet().register(buffer, offset, length);
    }

    @Override
    public void process(APDU apdu) {
      if (selectingApplet()) {
        return;
      }

      byte[] buffer = apdu.getBuffer();
      short received = apdu.setIncomingAndReceive();
      short length = apdu.getIncomingLength();
      byte[] request = new byte[length];
      short copied = 0;
      while (received > 0) {
        Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), request, copied, received);
        copied += received;
        received = copied < length ? apdu.receiveBytes(apdu.getOffsetCdata()) : 0;
      }

      byte[] identityAID = aidBytes(IDENTITY_AID);
      IdentityShareable identity = (IdentityShareable) JCSystem.getAppletShareableInterfaceObject(
        JCSystem.lookupAID(identityAID, (short) 0, (byte) identityAID.length),
        (byte) 0
      );
      if (buffer[ISO7816.OFFSET_INS] == 3) {
        if (!identity.checkSecretPIN(copyGlobal(request, (short) 0, length))) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        return;
      }

      byte[] index = copyGlobal(request, (short) 0, (short) 10);
      short keyLength = (short) (request[10] & 0xFF);
      byte[] key = copyGlobal(request, (short) 11, keyLength);
      short aliasOffset = (short) (11 + keyLength);
      short aliasLength = (short) (request[aliasOffset++] & 0xFF);
      byte[] alias = copyGlobal(request, aliasOffset, aliasLength);
      short dataOffset = (short) (aliasOffset + aliasLength);
      byte[] data = copyGlobal(request, dataOffset, (short) (length - dataOffset));
      try {
        CommunicationDataShareable result;
        IdentityCallerApplet.Data source = new IdentityCallerApplet.Data(data);
        if (buffer[ISO7816.OFFSET_INS] == 1) {
          result = identity.encryptData(null, index, key, alias, (short) 0x5AFE, null, source);
        } else {
          result = identity.decryptData(null, index, key, alias, null, source);
        }
        short resultLength = result.getLength();
        byte[] output = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, resultLength);
        result.read((short) 0, output, (short) 0, resultLength);
        apdu.setOutgoing();
        apdu.setOutgoingLength(resultLength);
        apdu.sendBytesLong(output, (short) 0, resultLength);
      } catch (CryptoException exception) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }
    }

    private byte[] copyGlobal(byte[] source, short offset, short length) {
      byte[] result = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, length);
      Util.arrayCopyNonAtomic(source, offset, result, (short) 0, length);
      return result;
    }
  }
}
