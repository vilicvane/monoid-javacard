package monoidsecuritykey;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.smartcardio.CardSimulator;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import javacard.framework.ISOException;
import monoid.SafeDataShareable;
import monoid.SafeItemShareable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CredentialTest {

  @BeforeEach
  public void initialize() {
    new CardSimulator();
  }

  @Test
  public void preservesEncodingAcrossStringLengthBoundariesAndOptionalFields() {
    int[] lengths = { 0, 23, 24, 255, 256 };
    String[] textHeaders = { "60", "77", "7818", "78ff", "790100" };
    String[] byteHeaders = { "40", "57", "5818", "58ff", "590100" };
    Credential reusable = null;

    for (int boundary = 0; boundary < lengths.length; boundary++) {
      byte[] value = filled(lengths[boundary], 0x61);
      String text = textHeaders[boundary] + Hex.toHexString(value);
      String bytes = byteHeaders[boundary] + Hex.toHexString(value);

      for (int optional = 0; optional < 4; optional++) {
        for (boolean resident : new boolean[] { false, true }) {
          Credential credential = new Credential(
            filled(32, 1),
            filled(32, 2),
            value,
            value,
            (optional & 1) != 0 ? value : null,
            (optional & 2) != 0 ? value : null,
            resident,
            filled(65, 4)
          );
          String expected =
            Integer.toHexString(0xA7 + Integer.bitCount(optional)) +
            "0101025820" +
            Hex.toHexString(filled(32, 1)) +
            "035820" +
            Hex.toHexString(filled(32, 2)) +
            "04" +
            text +
            "05" +
            bytes +
            ((optional & 1) != 0 ? "06" + text : "") +
            ((optional & 2) != 0 ? "07" + text : "") +
            (resident ? "08f5" : "08f4") +
            "095841" +
            Hex.toHexString(filled(65, 4));
          byte[] actual = new byte[credential.getLength()];
          for (int offset = 0; offset < actual.length; offset += 64) {
            credential.read(
              (short) offset,
              actual,
              (short) offset,
              (short) Math.min(64, actual.length - offset)
            );
          }
          Assertions.assertArrayEquals(Hex.decode(expected), actual);
          Assertions.assertEquals(actual.length, credential.getLength());
          Credential generated = Credential.create(
            filled(32, 1),
            filled(32, 2),
            value,
            value,
            (optional & 1) != 0 ? value : null,
            (optional & 2) != 0 ? value : null,
            resident,
            filled(65, 4),
            reusable
          );
          byte[] staged = new byte[generated.getLength()];
          generated.read((short) 0, staged, (short) 0, (short) staged.length);
          Assertions.assertArrayEquals(Hex.decode(expected), staged);
          if (generated.getLength() <= Credential.READ_BUFFER_LENGTH) {
            reusable = generated;
          }
        }
      }
    }
  }

  @Test
  public void preservesTheEncodedRecordLimit() {
    for (int length : new int[] { 1050, 1051, 1201 }) {
      Supplier<Credential> create = () ->
        new Credential(
          filled(32, 1),
          filled(32, 2),
          filled(length, 0x61),
          new byte[] { 3 },
          null,
          null,
          false,
          filled(65, 4)
        );
      if (length == 1050) {
        Assertions.assertEquals(CTAP.MAX_MESSAGE_LENGTH, create.get().getLength());
      } else {
        ISOException exception = Assertions.assertThrows(ISOException.class, create::get);
        Assertions.assertEquals(CTAP.LIMIT_EXCEEDED, exception.getReason());
      }
    }
  }

  @Test
  public void readsCompleteRecordsThroughDifferentBorrowedWindowLengths() {
    for (int textLength : new int[] { 0, 129, 512, 1050 }) {
      Credential original = new Credential(
        filled(32, 1),
        filled(32, 2),
        filled(textLength, 0x61),
        new byte[] { 3 },
        null,
        null,
        true,
        filled(65, 4)
      );
      int encodedLength = original.getLength();
      for (int windowLength : new int[] { 64, 128, 133, 256, 260, 1200 }) {
        byte[] window = new byte[windowLength];
        List<Integer> reads = new ArrayList<>();
        SafeDataShareable source = new SafeDataShareable() {
          @Override
          public short getLength() {
            return original.getLength();
          }

          @Override
          public void read(short offset, byte[] buffer, short bufferOffset, short length) {
            Assertions.assertSame(window, buffer);
            Assertions.assertEquals(reads.size() * windowLength, offset);
            Assertions.assertEquals(Math.min(windowLength, encodedLength - offset), length);
            reads.add((int) length);
            original.read(offset, buffer, bufferOffset, length);
          }
        };
        SafeItemShareable item = (SafeItemShareable) Proxy.newProxyInstance(
          SafeItemShareable.class.getClassLoader(),
          new Class<?>[] { SafeItemShareable.class },
          (proxy, method, arguments) -> {
            switch (method.getName()) {
              case "getData":
                return source;
              case "getIndex":
                return original.index();
              case "getKey":
                return original.key();
              default:
                throw new UnsupportedOperationException(method.getName());
            }
          }
        );

        Credential decoded = Credential.read(item, window);
        Assertions.assertEquals((encodedLength + windowLength - 1) / windowLength, reads.size());
        // A later response may overwrite all APDU scratch bytes without changing the credential.
        Arrays.fill(window, (byte) 0);
        byte[] expected = new byte[encodedLength];
        byte[] actual = new byte[decoded.getLength()];
        original.read((short) 0, expected, (short) 0, (short) expected.length);
        decoded.read((short) 0, actual, (short) 0, (short) actual.length);
        Assertions.assertArrayEquals(expected, actual);
      }
    }
  }

  private static byte[] filled(int length, int value) {
    byte[] bytes = new byte[length];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }
}
