package com.lucaskam.encryption.rsa.models;

import java.math.BigInteger;

public class Key {
    private BigInteger modulus;
    
    private BigInteger exponent;

    public Key(BigInteger modulus, BigInteger exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
    }

    public Key() {
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    public BigInteger getExponent() {
        return exponent;
    }

    public void setExponent(BigInteger exponent) {
        this.exponent = exponent;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("Key{");
        sb.append("exponent=").append(exponent);
        sb.append(", modulus=").append(modulus);
        sb.append('}');
        return sb.toString();
    }

    public static KeyBuilder builder() {
        return new KeyBuilder();
    }
    
}
