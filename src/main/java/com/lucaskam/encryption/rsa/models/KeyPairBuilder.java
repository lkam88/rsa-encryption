package com.lucaskam.encryption.rsa.models;

public class KeyPairBuilder {
    private KeyPair keyPair = new KeyPair();

    public KeyPairBuilder privateKey(Key key) {
        keyPair.setPrivateKey(key);
        return this;
    }

    public KeyPairBuilder publicKey(Key key) {
        keyPair.setPublicKey(key);
        return this;
    }

    public KeyPair build() {
        return keyPair;
    }
}
