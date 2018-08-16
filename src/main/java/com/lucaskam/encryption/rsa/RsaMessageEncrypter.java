package com.lucaskam.encryption.rsa;

import com.lucaskam.encryption.rsa.exceptions.MessageEncrypterException;
import com.lucaskam.encryption.rsa.models.KeyPair;
import com.lucaskam.encryption.rsa.models.Response;

import java.math.BigInteger;

public class RsaMessageEncrypter {

    private KeyStore keyStore;
    private RsaAlgorithm rsaAlgorithm;
    private KeyEncoder keyEncoder;
    private MessageEncoder messageEncoder;

    public RsaMessageEncrypter(RsaAlgorithm rsaAlgorithm, KeyEncoder keyEncoder, MessageEncoder messageEncoder, KeyStore keyStore) {
        this.rsaAlgorithm = rsaAlgorithm;
        this.keyEncoder = keyEncoder;
        this.messageEncoder = messageEncoder;
        this.keyStore = keyStore;
    }

    /**
     * Takes a message and generates an encrypted signature from the message.  The method will look for a private and public key in the key store and use those
     * to create the signature.  If the keys have not been generated, then it will create a 512 bit RSA encrypted private and public key.
     *
     * @param message Message to be encrypted
     * @return A model object that contains the original message, the signature, and public key.
     * @throws IllegalArgumentException                                         The input to the program is either missing or greater than 250 characters.
     * @throws com.lucaskam.encryption.rsa.exceptions.MessageEncrypterException Represents an error while trying to encrypt a message.
     */
    public Response encryptMessage(String message) throws MessageEncrypterException {
        if (message == null || message.isEmpty()) {
            throw new IllegalArgumentException("Message must not be null or empty.");
        } else if (message.length() > 250) {
            throw new IllegalArgumentException("Message must not be greater than 250 characters.");
        }


        try {
            KeyPair keyPair;
            if (keyStore.keysGenerated()) {
                keyPair = keyStore.readKeys();
            } else {
                keyPair = rsaAlgorithm.generatePublicAndPrivateKey();
                keyStore.writeKeys(keyPair);
            }

            String publicKey = String.format(KeyStore.PUBLIC_KEY_FORMAT, keyEncoder.encodePublicKey(keyPair.getPublicKey()));

            BigInteger encryptedMessage = rsaAlgorithm.encrypt(new BigInteger(message.getBytes("UTF-8")), keyPair.getPublicKey());

            String signature = messageEncoder.encodeEncryptedMessage(encryptedMessage);

            return Response.builder()
                    .message(message)
                    .signature(signature)
                    .pubKey(publicKey)
                    .build();
        } catch (Exception e) {
            throw new MessageEncrypterException("Unable to encrpyt message", e);
        }
    }

    /**
     * Takes a Base 64 encrypted signature an decrypt the original message.  The method will look for a private and public
     * key in the key store and use those decrypt the siganture.  If the keys have not been generated, then it will
     * create a 512 bit RSA encrypted private and public key.
     *
     * @param signature Base64 encoded encrypted siganture
     * @return A model object that contains the original message, the signature, and public key.
     * @throws IllegalArgumentException                                         The input to the program is either missing or greater than 250 characters.
     * @throws com.lucaskam.encryption.rsa.exceptions.MessageEncrypterException Represents an error while trying to decrypt a message.
     */
    public String decryptMessage(String signature) throws Exception {
        if (signature == null || signature.isEmpty()) {
            throw new IllegalArgumentException("Message must not be null or empty.");
        }

        KeyPair keyPair;
        if (keyStore.keysGenerated()) {
            keyPair = keyStore.readKeys();
        } else {
            keyPair = rsaAlgorithm.generatePublicAndPrivateKey();
            keyStore.writeKeys(keyPair);
        }

        BigInteger encryptedMessage = messageEncoder.decodeEncryptedMessage(signature);

        byte[] decryptedBytes = rsaAlgorithm.decrypt(encryptedMessage, keyPair.getPrivateKey()).toByteArray();

        return new String(decryptedBytes);
    }
}
