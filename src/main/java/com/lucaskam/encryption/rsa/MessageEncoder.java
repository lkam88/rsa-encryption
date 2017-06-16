package com.lucaskam.encryption.rsa;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class MessageEncoder {
    public BigInteger hashMessage(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
            return new BigInteger(hash);
        } catch (NoSuchAlgorithmException e) {
            // This shouldn't happen but we have to handle it anyways.
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public String encodeEncryptedMessage(BigInteger encryptedMessage) {
        byte[] bytes = encryptedMessage.toByteArray();
        return Base64.getEncoder().encodeToString(bytes);
    }
}
