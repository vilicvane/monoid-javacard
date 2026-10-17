package com.licel.jcardsim.crypto;

import java.security.SecureRandom;

/** jCardSim's KeyPair generator otherwise uses an unseeded generator per instance. */
class SecureRandomNullProvider extends SecureRandom {

  public SecureRandomNullProvider() {
    super();
  }
}
