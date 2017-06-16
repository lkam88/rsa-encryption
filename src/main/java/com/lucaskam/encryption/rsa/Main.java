package com.lucaskam.encryption.rsa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lucaskam.encryption.rsa.models.Response;

import java.io.File;
import java.util.Random;

public class Main {
    public static void main(String[] args) throws Exception {
        String message = args[0];

        RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator(new Random());
        RsaAlgorithm rsaAlgorithm = new RsaAlgorithm(randomNumberGenerator);

        KeyEncoder keyEncoder = new KeyEncoder();

        MessageEncoder messageEncoder = new MessageEncoder();

        RsaMessageEncrypter rsaMessageEncrypter = new RsaMessageEncrypter(rsaAlgorithm, keyEncoder, messageEncoder);
        Response response = rsaMessageEncrypter.encryptMessage(message, new File("rsa_key"), new File("rsa_key.pub"));
        ObjectMapper objectMapper = new ObjectMapper();
        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(response));
    }
}