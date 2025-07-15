package applet;

import javacard.framework.*;
import javacard.security.*;

public class HelloWorldApplet extends Applet implements AppletEvent {

	private static final byte[] helloWorld = { 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!' };

	private static KeyAgreement keyAgreement;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, true);

		// Signature signature = Signature.getInstance(Signature.ALG_HMAC_SHA_512,
		// false);

		new HelloWorldApplet();
	}

	public void uninstall() {
		keyAgreement = null;
	}

	public HelloWorldApplet() {
		register();
	}

	public void process(APDU apdu) {
		sendHelloWorld(apdu);
	}

	// part of
	// https://github.com/devrandom/javacard-helloworld/blob/master/src/main/java/org/gitian/javacard/HelloWorldApplet.java#L38
	private void sendHelloWorld(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short length = (short) helloWorld.length;
		Util.arrayCopyNonAtomic(helloWorld, (short) 0, buffer, (short) 0, length);
		apdu.setOutgoingAndSend((short) 0, length);
	}
}
