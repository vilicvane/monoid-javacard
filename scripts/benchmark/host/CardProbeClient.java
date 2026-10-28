import java.io.BufferedReader;
import java.io.InputStreamReader;
import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public final class CardProbeClient {

  public static void main(String[] arguments) throws Exception {
    CardTerminal terminal = TerminalFactory.getDefault().terminals().getTerminal(arguments[0]);

    if (terminal == null || !terminal.isCardPresent()) {
      throw new IllegalStateException("Selected reader has no card");
    }

    Card card = terminal.connect("*");
    boolean exclusive = false;

    try {
      card.beginExclusive();
      exclusive = true;
      System.out.println(
        "{\"reader\":\"" +
        escape(terminal.getName()) +
        "\",\"atr\":\"" +
        hex(card.getATR().getBytes()) +
        "\",\"protocol\":\"" +
        card.getProtocol() +
        "\"}"
      );

      BufferedReader input = new BufferedReader(new InputStreamReader(System.in));

      for (String line; (line = input.readLine()) != null; ) {
        CommandAPDU command = new CommandAPDU(bytes(line));
        long started = System.nanoTime();
        ResponseAPDU response = card.getBasicChannel().transmit(command);
        long finished = System.nanoTime();

        // Stop timing before JSON/hex formatting or stdout; include only synchronous PC/SC transmit.
        System.out.println(
          "{\"response\":\"" +
          hex(response.getBytes()) +
          "\",\"elapsedMs\":" +
          ((finished - started) / 1000000.0) +
          "}"
        );
      }
    } finally {
      try {
        if (exclusive) card.endExclusive();
      } finally {
        card.disconnect(false);
      }
    }
  }

  private static byte[] bytes(String value) {
    byte[] result = new byte[value.length() / 2];

    for (int index = 0; index < result.length; index++) {
      result[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
    }

    return result;
  }

  private static String hex(byte[] value) {
    StringBuilder result = new StringBuilder();

    for (byte item : value) result.append(String.format("%02x", item & 255));

    return result.toString();
  }

  private static String escape(String value) {
    return value
      .replace("\\", "\\\\")
      .replace("\"", "\\\"")
      .replace("\n", "\\n")
      .replace("\r", "\\r");
  }
}
