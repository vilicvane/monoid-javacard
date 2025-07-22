package tests;

import com.licel.jcardsim.smartcardio.CardSimulator;
import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.RunConfig;
import cz.muni.fi.crocs.rcard.client.Util;
import java.util.ArrayList;
import java.util.Arrays;
import javacard.framework.AID;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class AppletTest {

  protected byte[] aid;

  protected CardType cardType;
  protected CardSimulator simulator;

  public AppletTest(AID aid, CardType cardType) {
    this.aid = aidBytes(aid);
    this.cardType = cardType;

    if (cardType == CardType.JCARDSIMLOCAL) {
      System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
      System.setProperty("com.licel.jcardsim.sign.dsasigner.computedhash", "1");

      this.simulator = new CardSimulator();
    }
  }

  /**
   * Creates card manager and connects to the card.
   *
   * @return
   * @throws Exception
   */
  public CardManager connect() throws Exception {
    CardManager manager = new CardManager(true, aid);

    switch (cardType) {
      case JCARDSIMLOCAL:
        manager.connectJCardSimLocalSimulator(simulator);
        break;
      case PHYSICAL:
        manager.connect(RunConfig.getDefaultConfig().setTestCardType(cardType));
        break;
      default:
        throw new IllegalArgumentException("Unsupported card type: " + cardType);
    }

    return manager;
  }

  /**
   * Convenience method for connecting and sending
   * @param cmd
   * @return
   */
  public ResponseAPDU connectAndSend(CommandAPDU cmd) throws Exception {
    return connect().transmit(cmd);
  }

  public static CommandAPDU apdu(int cla, int ins, int p1, int p2, byte[] data) {
    return new CommandAPDU(cla, ins, p1, p2, data);
  }

  public static CommandAPDU apdu(int cla, int ins, int p1, int p2, String data) {
    return new CommandAPDU(cla, ins, p1, p2, Util.hexStringToByteArray(data));
  }

  public static CommandAPDU apdu(int cla, int ins, int p1, int p2) {
    return new CommandAPDU(cla, ins, p1, p2);
  }

  /**
   * Convenience method for building APDU command
   * @param data
   * @return
   */
  public static CommandAPDU apdu(String data) {
    return new CommandAPDU(Util.hexStringToByteArray(data));
  }

  /**
   * Convenience method for building APDU command
   * @param data
   * @return
   */
  public static CommandAPDU apdu(byte[] data) {
    return new CommandAPDU(data);
  }

  public static byte[] aidBytes(String aid) {
    return Util.hexStringToByteArray(aid);
  }

  public static byte[] aidBytes(AID aid) {
    byte[] buffer = new byte[16];
    short length = aid.getBytes(buffer, (short) 0);
    return Arrays.copyOf(buffer, length);
  }

  /**
   * Sending command to the card.
   * Enables to send init commands before the main one.
   *
   * @param manager
   * @param command
   * @param initCommands
   * @return
   * @throws CardException
   */
  public ResponseAPDU sendCommandWithInitSequence(
    CardManager manager,
    String command,
    ArrayList<String> initCommands
  ) throws CardException {
    if (initCommands != null) {
      for (String cmd : initCommands) {
        manager.getChannel().transmit(apdu(cmd));
      }
    }

    return manager.getChannel().transmit(apdu(command));
  }

  public CardType getCardType() {
    return cardType;
  }

  public AppletTest setCardType(CardType cardType) {
    this.cardType = cardType;
    return this;
  }
}
