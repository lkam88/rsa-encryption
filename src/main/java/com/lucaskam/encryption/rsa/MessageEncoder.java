package com.lucaskam.encryption.rsa;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class MessageEncoder {
    /**
     * Takes a string, hashes it using SHA-256, and returns an integer representation of the String.
     *
     * @param message Messaged to be hashed.
     * @return An integer representing a hash of the passed message.
     */
    public BigInteger hashMessage(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_16));
            return new BigInteger(hash);
        } catch (NoSuchAlgorithmException e) {
            // This shouldn't happen but we have to handle it anyways.
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * Takes the integer result of an RSA encrypted message and returns a Base64 String representation of the encrypted message.
     *
     * @param encryptedMessage An integer representing the result of an RSA encryption of a message.
     * @return The Base 64 String representation of the passed encrypted message.
     */
    public String encodeEncryptedMessage(BigInteger encryptedMessage) {
        byte[] bytes = encryptedMessage.toByteArray();
        return Base64.getEncoder().encodeToString(bytes);
    }
}
