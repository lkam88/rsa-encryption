package com.lucaskam.encryption.rsa.exceptions;

/**
 * This exception signals that an error occurred while encrypting or decrypting a message.
 * This is a wrapper exception and the most likely cause would be The most likely
 * caused exception would be a {@link com.lucaskam.encryption.rsa.exceptions.KeyStoreException}
 */
public class MessageEncrypterException extends Exception {
    public MessageEncrypterException(String message, Exception exception) {
        super(message, exception);
    }
}
