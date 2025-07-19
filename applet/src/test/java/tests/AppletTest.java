package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.Util;
import javacard.framework.AID;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import com.licel.jcardsim.smartcardio.CardSimulator;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Base Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda, Dusan Klinec (ph4r05)
 */
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

    if (cardType == CardType.JCARDSIMLOCAL) {
      manager.connectJCardSimLocalSimulator(simulator);
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
   * @param cardMngr
   * @param command
   * @param initCommands
   * @return
   * @throws CardException
   */
  public ResponseAPDU sendCommandWithInitSequence(CardManager cardMngr, String command,
      ArrayList<String> initCommands) throws CardException {
    if (initCommands != null) {
      for (String cmd : initCommands) {
        cardMngr.getChannel().transmit(apdu(cmd));
      }
    }

    final ResponseAPDU resp = cardMngr.getChannel().transmit(apdu(command));
    return resp;
  }

  public CardType getCardType() {
    return cardType;
  }

  public AppletTest setCardType(CardType cardType) {
    this.cardType = cardType;
    return this;
  }
}
