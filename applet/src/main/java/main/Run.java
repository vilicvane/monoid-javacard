package main;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import applet.MainApplet;
import javacard.framework.AID;
import monoid.MonoidApplet;
import monoidkeystore.MonoidKeystoreApplet;

import javax.smartcardio.*;

public class Run {
    public static void main(String[] args) {
        // 1. create simulator
        CardSimulator simulator = new CardSimulator();

        // 2. install applet
        AID monoidKeystoreAID = AIDUtil.create("F06D6F6E6F69640001");
        AID monoidAID = AIDUtil.create("F06D6F6E6F69640101");

        simulator.installApplet(monoidKeystoreAID, MonoidKeystoreApplet.class);
        simulator.installApplet(monoidAID, MonoidApplet.class);

        // 3. select applet
        simulator.selectApplet(monoidKeystoreAID);
        simulator.selectApplet(monoidAID);

        // // 2. install applet
        // AID aid = AIDUtil.create("FF00000000");

        // simulator.installApplet(aid, MainApplet.class);

        // // 3. select applet
        // simulator.selectApplet(aid);

        // 4. send APDU

        for (short index = 0; index < 3; index++) {
            CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x90, 0x00, 0x00);

            ResponseAPDU response = simulator.transmitCommand(commandAPDU);

            System.out.println("SW: 0x" + Integer.toHexString(response.getSW()) + " (" + response.getSW() + ")");
            System.out.println(new String(response.getData()));
        }
    }

}
