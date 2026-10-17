// Generated from monoidsafeidentity/GHASH.java by Inplate.
package monoidsafe;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/** GHASH from NIST SP 800-38D, using the MSB-first polynomial representation. */
public final class GHASH {

  private final short[] h;
  private final short[] y;

  public GHASH() {
    h = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_RESET);
    y = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_RESET);
  }

  public void init(byte[] hashKey, short offset) {
    for (short index = 0; index < 8; index++) {
      h[index] = Util.getShort(hashKey, offset);
      y[index] = 0;
      offset += 2;
    }
  }

  /**
   * Adds one block of at most 16 bytes, padding that block with zeros. Calls
   * represent complete GHASH blocks, not arbitrary fragments of a byte stream.
   */
  public void update(byte[] input, short offset, short length) {
    short v0 = h[0];
    short v1 = h[1];
    short v2 = h[2];
    short v3 = h[3];
    short v4 = h[4];
    short v5 = h[5];
    short v6 = h[6];
    short v7 = h[7];
    short z0 = 0;
    short z1 = 0;
    short z2 = 0;
    short z3 = 0;
    short z4 = 0;
    short z5 = 0;
    short z6 = 0;
    short z7 = 0;

    // Algorithm 1: eight 16-bit words, with no secret-dependent branches or indexes.
    for (short index = 0; index < 8; index++) {
      short word = y[index];

      if (length >= 2) {
        word ^= Util.getShort(input, offset);
        offset += 2;
        length -= 2;
      } else if (length == 1) {
        word ^= (short) (input[offset] << 8);
        length = 0;
      }

      for (short bit = 0; bit < 16; bit++) {
        short mask = (short) (word >> 15);
        z0 ^= v0 & mask;
        z1 ^= v1 & mask;
        z2 ^= v2 & mask;
        z3 ^= v3 & mask;
        z4 ^= v4 & mask;
        z5 ^= v5 & mask;
        z6 ^= v6 & mask;
        z7 ^= v7 & mask;

        mask = (short) -(v7 & 1);
        v7 = (short) (((v7 >> 1) & 0x7FFF) | (v6 << 15));
        v6 = (short) (((v6 >> 1) & 0x7FFF) | (v5 << 15));
        v5 = (short) (((v5 >> 1) & 0x7FFF) | (v4 << 15));
        v4 = (short) (((v4 >> 1) & 0x7FFF) | (v3 << 15));
        v3 = (short) (((v3 >> 1) & 0x7FFF) | (v2 << 15));
        v2 = (short) (((v2 >> 1) & 0x7FFF) | (v1 << 15));
        v1 = (short) (((v1 >> 1) & 0x7FFF) | (v0 << 15));
        v0 = (short) (((v0 >> 1) & 0x7FFF) ^ ((short) 0xE100 & mask));
        word <<= 1;
      }
    }

    y[0] = z0;
    y[1] = z1;
    y[2] = z2;
    y[3] = z3;
    y[4] = z4;
    y[5] = z5;
    y[6] = z6;
    y[7] = z7;
  }

  public void output(byte[] out, short offset) {
    for (short index = 0; index < 8; index++) {
      Util.setShort(out, offset, y[index]);
      offset += 2;
    }
  }
}
