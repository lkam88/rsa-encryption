package com.lucaskam.encryption.rsa;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Base64;

public class MessageEncoder {
    /**
     * Takes the integer result of an RSA encrypted message and returns a Base64 String representation of the encrypted message.
     *
     * @param encryptedMessage An integer representing the result of an RSA encryption of a message.
     * @return The Base 64 String representation of the passed encrypted message.
     */
    public String encodeEncryptedMessage(BigInteger encryptedMessage) {
        byte[] bytes = encryptedMessage.toByteArray();
        try {
            return new String(Base64.getEncoder().encode(bytes), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public BigInteger decodeEncryptedMessage(String encryptedMessage) throws UnsupportedEncodingException {
        try {
            byte[] bytes = encryptedMessage.getBytes("UTF-8");
            byte[] decode = Base64.getDecoder().decode(bytes);
            return new BigInteger(decode);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw e;
        }
    }
}
