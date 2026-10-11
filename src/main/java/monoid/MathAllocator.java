// Derived from JCEd25519 / JCMathLib 2.1-rc.1 (MIT).
// Copyright (c) 2022 Antonin Dufka; JCMathLib authors Vasilios Mavroudis, Petr Svenda, Antonin Dufka.
// Source, changes and licenses: third-party/jced25519/PROVENANCE.md.
package monoid;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public final class MathAllocator {

  short allocatedInRAM = 0;
  short allocatedInEEPROM = 0;
  byte[] allocatorTypes;

  public static final byte ARRAY_A = 0;
  public static final byte ARRAY_B = 1;
  public static final byte BN_WORD = 2;
  public static final byte BN_A = 3;
  public static final byte BN_B = 4;
  public static final byte BN_C = 5;
  public static final byte BN_D = 6;
  public static final byte BN_E = 7;
  public static final byte BN_F = 8;
  public static final byte BN_G = 9;

  public static final byte EC_BN_A = 10;
  public static final byte EC_BN_B = 11;
  public static final byte EC_BN_C = 12;
  public static final byte EC_BN_D = 13;
  public static final byte EC_BN_E = 14;
  public static final byte EC_BN_F = 15;
  public static final byte POINT_ARRAY_A = 16;
  public static final byte POINT_ARRAY_B = 17;
  public static final byte HASH_ARRAY = 18;

  public static final short ALLOCATOR_TYPE_ARRAY_LENGTH = (short) (HASH_ARRAY + 1);

  /**
   * Creates new allocator control object, resets performance counters
   */
  public MathAllocator() {
    allocatorTypes = new byte[ALLOCATOR_TYPE_ARRAY_LENGTH];
    setAllAllocatorsRAM();
    resetAllocatorCounters();
  }

  /**
   * All type of allocator for all object as EEPROM
   */
  public final void setAllAllocatorsEEPROM() {
    Util.arrayFillNonAtomic(
      allocatorTypes,
      (short) 0,
      (short) allocatorTypes.length,
      JCSystem.MEMORY_TYPE_PERSISTENT
    );
  }

  /**
   * All type of allocator for all object as RAM
   */
  public void setAllAllocatorsRAM() {
    Util.arrayFillNonAtomic(
      allocatorTypes,
      (short) 0,
      (short) allocatorTypes.length,
      JCSystem.MEMORY_TYPE_TRANSIENT_RESET
    );
  }

  /**
   * All type of allocator for selected object as RAM (faster), rest EEPROM (saving RAM)
   * The current settings is heuristically obtained from measurements of performance of Bignat and ECPoint operations
   */
  public void setAllocatorsTradeoff() {
    // Set initial allocators into EEPROM
    setAllAllocatorsEEPROM();

    // Put only the most perfromance relevant ones into RAM
    allocatorTypes[ARRAY_A] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[ARRAY_B] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[BN_WORD] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[BN_A] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[BN_B] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[BN_C] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[BN_D] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[BN_E] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[BN_F] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[BN_G] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[EC_BN_B] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[EC_BN_C] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[POINT_ARRAY_A] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    allocatorTypes[POINT_ARRAY_B] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
  }

  /**
   * Allocates new byte[] array with provided length either in RAM or EEPROM based on an allocator type.
   * Method updates internal counters of bytes allocated with specific allocator. Use {@code getAllocatedInRAM()}
   * or {@code getAllocatedInEEPROM} for counters readout.
   * @param length    length of array
   * @param allocatorType type of allocator
   * @return allocated array
   */
  public byte[] allocateByteArray(short length, byte allocatorType) {
    switch (allocatorType) {
      case JCSystem.MEMORY_TYPE_PERSISTENT:
        allocatedInEEPROM += length;
        return new byte[length];
      case JCSystem.MEMORY_TYPE_TRANSIENT_RESET:
        allocatedInRAM += length;
        return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_RESET);
      case JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT:
        allocatedInRAM += length;
        return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);
    }

    return null;
  }

  /**
   * Allocates new short[] array with provided length either in RAM or EEPROM based on an allocator type.
   * Method updates internal counters of bytes allocated with specific allocator. Use {@code getAllocatedInRAM()}
   * or {@code getAllocatedInEEPROM} for counters readout.
   * @param length length of array
   * @param allocatorType type of allocator
   * @return allocated array
   */
  public short[] allocateShortArray(short length, byte allocatorType) {
    switch (allocatorType) {
      case JCSystem.MEMORY_TYPE_PERSISTENT:
        allocatedInEEPROM += (short) (2 * length);
        return new short[length];
      case JCSystem.MEMORY_TYPE_TRANSIENT_RESET:
        allocatedInRAM += (short) (2 * length);
        return JCSystem.makeTransientShortArray(length, JCSystem.CLEAR_ON_RESET);
      case JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT:
        allocatedInRAM += (short) (2 * length);
        return JCSystem.makeTransientShortArray(length, JCSystem.CLEAR_ON_DESELECT);
    }

    return null;
  }

  /**
   * Returns pre-set allocator type for provided object identified by unique allocatorId
   * @param allocatorId unique id of target object
   * @return allocator type
   */
  public byte getAllocatorType(short allocatorId) {
    if (allocatorId >= 0 && allocatorId <= (short) allocatorTypes.length) {
      return allocatorTypes[allocatorId];
    } else {
      ISOException.throwIt(MathStatus.SW_ALLOCATOR_INVALID_ID);

      return -1;
    }
  }

  /**
   * Returns number of bytes allocated in RAM via {@code allocateByteArray()} since last reset of counters.
   * @return number of bytes allocated in RAM via this control object
   */
  public short getAllocatedInRAM() {
    return allocatedInRAM;
  }

  /**
   * Returns number of bytes allocated in EEPROM via {@code allocateByteArray()}
   * since last reset of counters.
   *
   * @return number of bytes allocated in EEPROM via this control object
   */
  public short getAllocatedInEEPROM() {
    return allocatedInEEPROM;
  }

  /**
   * Resets counters of allocated bytes in RAM and EEPROM
   */
  public final void resetAllocatorCounters() {
    allocatedInRAM = 0;
    allocatedInEEPROM = 0;
  }
}
