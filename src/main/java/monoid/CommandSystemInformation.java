package monoid;

import javacard.framework.JCSystem;

public class CommandSystemInformation extends Command {

  @Override
  protected void run() {
    reader.map();

    writer.map((short) 3);
    {
      writeVersionsKeyValue(writer);

      writeMemoriesKeyValue(writer);

      writeFeaturesKeyValue(writer);
    }
  }

  private static void writeVersionsKeyValue(CBORWriter writer) {
    writer.text(Text.versions);
    writer.map((short) 2);
    {
      writer.text(Text.monoid);
      writer.integer(MonoidApplet.version);

      writer.text(Text.javacard);
      writer.array((short) 2);
      {
        writer.integer((short) (JCSystem.getVersion() >> 8));
        writer.integer((short) (JCSystem.getVersion() & 0xFF));
      }
    }
  }

  private static void writeMemoriesKeyValue(CBORWriter writer) {
    writer.text(Text.memories);
    writer.map((short) 2);
    {
      writer.text(Text.persistent);
      writer.map((short) 1);
      {
        writer.text(Text.available);
        writer.integer(JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
      }

      writer.text(Text.transient_);
      writer.map((short) 2);
      {
        writer.text(Text.reset);
        writer.integer(JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));

        writer.text(Text.deselect);
        writer.integer(JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
      }
    }
  }

  public static void writeFeaturesKeyValue(CBORWriter writer) {
    writer.text(Text.features);
    writer.map((short) 1);
    {
      writer.text(Text.curves);
      writer.array((short) 2);
      {
        writeCurveFeatures(writer, WeierstrassCurve.SECP256k1, Signer.CIPHER_ECDSA);
        writeCurveFeatures(writer, EdwardsCurve.ED25519, Signer.CIPHER_EDDSA);
      }
    }
  }

  private static void writeCurveFeatures(CBORWriter writer, byte[] name, byte[] cipher) {
    writer.map((short) 2);
    {
      writer.text(Text.name);
      writer.text(name);

      writer.text(Text.ciphers);
      writer.array((short) 1);
      writer.text(cipher);
    }
  }
}
