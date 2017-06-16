package com.lucaskam.encryption.rsa;

import com.lucaskam.encryption.rsa.exceptions.KeyStoreException;
import com.lucaskam.encryption.rsa.models.Key;
import com.lucaskam.encryption.rsa.models.KeyPair;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class KeyStore {
    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n";
    public static final String END_PRIVATE_KEY = "\n-----END PRIVATE KEY-----\n";
    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n";
    public static final String END_PUBLIC_KEY = "\n-----END PUBLIC KEY-----\n";
    public static final String PRIVATE_KEY_FORMAT = BEGIN_PRIVATE_KEY + "%s" + END_PRIVATE_KEY;
    public static final String PUBLIC_KEY_FORMAT = BEGIN_PUBLIC_KEY + "%s" + END_PUBLIC_KEY;

    public KeyEncoder keyEncoder;

    private File privateKeyFile;

    private File publicKeyFile;

    public KeyStore(KeyEncoder keyEncoder, File privateKeyFile, File publicKeyFile) {
        this.keyEncoder = keyEncoder;
        this.privateKeyFile = privateKeyFile;
        this.publicKeyFile = publicKeyFile;
    }

    public boolean keysGenerated() {
        return privateKeyFile.exists() && publicKeyFile.exists();
    }

    public KeyPair readKeys() throws KeyStoreException {
        try {
            String privateKeyString = readFile(privateKeyFile, true);
            String publicKeyString = readFile(publicKeyFile, false);

            Key privateKey = keyEncoder.decodePrivateKey(privateKeyString);
            Key publicKey = keyEncoder.decodePublicKey(publicKeyString);
            return KeyPair.builder()
                          .privateKey(privateKey)
                          .publicKey(publicKey)
                          .build();
        } catch (Exception e) {
            throw new KeyStoreException("Unable read keys to file system.", e);
        }
    }

    private String readFile(File keyFile, boolean privateKey) throws IOException {
        byte[] bytes = Files.readAllBytes(Paths.get(keyFile.getPath()));
        String formattedKey = new String(bytes);
        String finalKey;
        // I'm not happy with this implementation.  I think I could use some fancy Regex to help me, but this will work for now.
        if (privateKey) {
            finalKey = formattedKey.replace(BEGIN_PRIVATE_KEY, "").replace(END_PRIVATE_KEY, "");
        } else {
            finalKey = formattedKey.replace(BEGIN_PUBLIC_KEY, "").replace(END_PUBLIC_KEY, "");
        }
        return finalKey;
    }

    public KeyPair writeKeys(KeyPair keyPair) throws KeyStoreException {
        try {
            String privateKeyString = keyEncoder.encodePrivateKey(keyPair.getPrivateKey());
            String publicKeyString = keyEncoder.encodePublicKey(keyPair.getPublicKey());

            writeFile(privateKeyString, privateKeyFile, PRIVATE_KEY_FORMAT);
            writeFile(publicKeyString, publicKeyFile, PUBLIC_KEY_FORMAT);
        } catch (Exception e) {
            throw new KeyStoreException("Unable write keys to file system.", e);
        }

        return null;
    }

    private void writeFile(String keyString, File keyFile, String format) throws IOException {
        try (FileWriter fileWriter = new FileWriter(keyFile)) {
            try (BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)) {
                bufferedWriter.write(String.format(format, keyString));
            }
        }
    }
}
