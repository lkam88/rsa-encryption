package com.lucaskam.encryption.rsa.models;

import java.math.BigInteger;

public class KeyBuilder {
    private Key key = new Key();

    public KeyBuilder() {
    }

    public KeyBuilder modulus(BigInteger modulus) {
        key.setModulus(modulus);
        return this;
    }

    public KeyBuilder exponent(BigInteger exponent) {
        key.setExponent(exponent);
        return this;
    }

    public Key build() {
        return key;
    }
}
