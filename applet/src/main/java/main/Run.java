package main;

import javacard.framework.AID;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import monoid.MonoidApplet;
import monoidsafe.MonoidSafeApplet;

import javax.smartcardio.*;

public class Run {
  public static void main(String[] args) {
    // 1. create simulator
    CardSimulator simulator = new CardSimulator();

    // 2. install applet
    AID monoidSafeAID = AIDUtil.create("F16D6F6E6F696400010001");
    AID monoidAID = AIDUtil.create("F16D6F6E6F696401010001");

    simulator.installApplet(monoidSafeAID, MonoidSafeApplet.class);
    simulator.installApplet(monoidAID, MonoidApplet.class);

    // 3. select applet
    // simulator.selectApplet(monoidSafeAID);
    simulator.selectApplet(monoidAID);

    // // 2. install applet
    // AID aid = AIDUtil.create("FF00000000");

    // simulator.installApplet(aid, MainApplet.class);

    // // 3. select applet
    // simulator.selectApplet(aid);

    // 4. send APDU

    CommandAPDU[] commands = new CommandAPDU[] {
        new CommandAPDU(0x00, 0x20, 0x00, 0x00),
        new CommandAPDU(0x00, 0x21, 0x00, 0x00, Hex.decode("A26370696E663838383838386473616665F5")),
        // new CommandAPDU(0x00, 0x01, 0x00, 0x00),
        // new CommandAPDU(0x00, 0x04, 0x00, 0x00,
        //     Hex.decode(
        //         "B9FAA9F03F077DA860D85CBFBFF7CB690555FD356A8804E893D46D8B9E4929E566215D7E6BFC60078F9A2F086C0BCE2180DB69A2D430BE821ABA9A269AD01B90"
        //             +
        //             "00000000")),
    };

    for (CommandAPDU commandAPDU : commands) {
      System.out.print("Command: ");
      printBytes(commandAPDU.getBytes());

      ResponseAPDU response = simulator.transmitCommand(commandAPDU);

      System.out.print("Response: ");
      printBytes(response.getData());

      System.out.println("SW: 0x" + Integer.toHexString(response.getSW()) + " (" + response.getSW() + ")");
    }
  }

  private static final void printBytes(byte[] data) {
    StringBuilder responseHex = new StringBuilder();
    for (byte b : data) {
      responseHex.append(String.format("%02X", b));
    }
    System.out.println(responseHex);
  }

}
