package com.lucaskam.encryption.rsa.models;

public class KeyPair {
    private Key privateKey;
    private Key publicKey;

    public KeyPair(Key privateKey, Key publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public KeyPair() {
    }

    public Key getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(Key privateKey) {
        this.privateKey = privateKey;
    }

    public Key getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(Key publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("KeyPair{");
        sb.append("privateKey=").append(privateKey);
        sb.append(", publicKey=").append(publicKey);
        sb.append('}');
        return sb.toString();
    }

    public static KeyPairBuilder builder() {
        return new KeyPairBuilder();
    }

}

