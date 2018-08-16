package com.lucaskam.encryption.rsa.exceptions;

/**
 * This exception signals that there was problem either read or writing keys to the key store.  The most likely cause
 * would be that the Java process doesn't have the correct permissions for the file system.
 */
public class KeyStoreException extends Exception {
    public KeyStoreException(String s, Exception e) {
        super(s,e);
    }
}
