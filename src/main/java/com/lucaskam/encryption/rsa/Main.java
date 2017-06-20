package com.lucaskam.encryption.rsa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lucaskam.encryption.rsa.models.Response;

import java.io.File;
import java.util.Random;

public class Main {

    /**
     * The main entry point for the program.  This program takes a single input of a String with a maximum length of 250 characters and prints to the console a
     * * JSON * object containing the original message, a signature of the message using RSA encryption, and the public key that was used to encrypt the
     * message. * The program will read private and public key from the file system at ./rsa_key and ./rsa_key.pub respectively.  If the keys don't exist on the
     * file system, then the program will generate a pair of 512 bit RSA private and public keys.
     */
    public static void main(String[] args) throws Exception {
        String message = args[0];

        RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator(new Random());
        RsaAlgorithm rsaAlgorithm = new RsaAlgorithm(randomNumberGenerator);

        KeyEncoder keyEncoder = new KeyEncoder();

        MessageEncoder messageEncoder = new MessageEncoder();

        File privateKeyFile = new File("rsa_key");
        File publicKeyFile = new File("rsa_key.pub");

        KeyStore keyStore = new KeyStore(keyEncoder, privateKeyFile, publicKeyFile);

        RsaMessageEncrypter rsaMessageEncrypter = new RsaMessageEncrypter(rsaAlgorithm, keyEncoder, messageEncoder, keyStore);
        Response response = rsaMessageEncrypter.encryptMessage(message);
        ObjectMapper objectMapper = new ObjectMapper();
        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(response));
    }
}