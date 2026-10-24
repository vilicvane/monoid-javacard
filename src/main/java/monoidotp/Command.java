package monoidotp;

import monoidlib.CBORApduReader;
import monoidlib.CBORApduWriter;

abstract class Command {

  protected static CBORApduReader reader;
  protected static CBORApduWriter writer;

  private static Command hello;
  private static Command challenge;
  private static Command prepare;
  private static Command calculate;

  static void init() {
    reader = new CBORApduReader();
    writer = new CBORApduWriter();

    hello = new CommandHello();
    challenge = new CommandChallenge();
    prepare = new CommandPrepare();
    calculate = new CommandCalculate();
  }

  static void dispose() {
    reader = null;
    writer = null;

    hello = null;
    challenge = null;
    prepare = null;
    calculate = null;
  }

  static Command get(byte instruction) {
    switch (instruction) {
      case 0x20:
        return hello;
      case 0x21:
        return challenge;
      case 0x22:
        return prepare;
      case 0x23:
        return calculate;
      default:
        return null;
    }
  }

  void executeCommand() {
    writer.reset();

    try {
      run();
    } catch (RuntimeException exception) {
      writer.reset();
      throw exception;
    }

    writer.send();
  }

  protected abstract void run();
}
