package com.lucaskam.encryption.rsa;

import com.lucaskam.encryption.rsa.models.KeyPair;
import com.lucaskam.encryption.rsa.models.Response;

import java.io.File;
import java.math.BigInteger;

public class RsaMessageEncrypter {

    private RsaAlgorithm rsaAlgorithm;
    private KeyEncoder keyEncoder;
    private MessageEncoder messageEncoder;

    public RsaMessageEncrypter(RsaAlgorithm rsaAlgorithm, KeyEncoder keyEncoder, MessageEncoder messageEncoder) {
        this.rsaAlgorithm = rsaAlgorithm;
        this.keyEncoder = keyEncoder;
        this.messageEncoder = messageEncoder;
    }

    public Response encryptMessage(String message, File privateKeyFile, File publicKeyFile) throws Exception {
        KeyStore keyStore = new KeyStore(keyEncoder, privateKeyFile, publicKeyFile);

        KeyPair keyPair;
        if (keyStore.keysGenerated()) {
            keyPair = keyStore.readKeys();
        } else {
            keyPair = rsaAlgorithm.generatePublicAndPrivateKey();
            keyStore.writeKeys(keyPair);
        }
        
        String publicKey = String.format(KeyStore.PUBLIC_KEY_FORMAT, keyEncoder.encodePublicKey(keyPair.getPublicKey()));


        BigInteger hashedMessage = messageEncoder.hashMessage(message);

//        BigInteger encryptedMessage = rsaAlgorithm.encrypt(hashedMessage, keyPair.getPublicKey());

//        String signature = messageEncoder.encodeEncryptedMessage(encryptedMessage);
//
//        System.out.println(signature);
        
        return Response.builder()
            .message(message)
            .signature("signature")
            .pubKey(publicKey)
            .build();
    }
}
