package com.lucaskam.encryption.rsa;

import com.lucaskam.encryption.rsa.models.Key;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class KeyEncoder {
    public String encodePrivateKey(Key privateKey) throws InvalidKeySpecException {
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(privateKey.getModulus(),
                                                                 privateKey.getExponent());
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey rsaPrivateKey = keyFactory.generatePrivate(privateKeySpec);
            return new String(Base64.getEncoder().encode(rsaPrivateKey.getEncoded()));
        } catch (NoSuchAlgorithmException ignore) {
            // This shouldn't happen but we have to handle it anyways.
            ignore.printStackTrace();
            throw new RuntimeException(ignore);
        }
    }

    public String encodePublicKey(Key publicKey) throws InvalidKeySpecException {
        try {
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(publicKey.getModulus(),
                                                                  publicKey.getExponent());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey rsaPublicKey = keyFactory.generatePublic(publicKeySpec);
            return new String(Base64.getEncoder().encode(rsaPublicKey.getEncoded()));
        } catch (NoSuchAlgorithmException ignore) {
            // This shouldn't happen but we have to handle it anyways.
            ignore.printStackTrace();
            throw new RuntimeException(ignore);
        }
    }

    public Key decodePrivateKey(String encodedPrivateKey) throws InvalidKeySpecException {
        byte[] decodedBytes = Base64.getDecoder().decode(encodedPrivateKey);
        PKCS8EncodedKeySpec encodedPrivateKeySpec = new PKCS8EncodedKeySpec(decodedBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(encodedPrivateKeySpec);

            return Key.builder()
                      .modulus(rsaPrivateKey.getModulus())
                      .exponent(rsaPrivateKey.getPrivateExponent())
                      .build();
        } catch (NoSuchAlgorithmException ignore) {
            // This shouldn't happen but we have to handle it anyways.
            ignore.printStackTrace();
            throw new RuntimeException(ignore);
        }

    }

    public Key decodePublicKey(String encodedPublicKey) throws InvalidKeySpecException {
        byte[] decodedBytes = Base64.getDecoder().decode(encodedPublicKey);
        X509EncodedKeySpec encodedPublicKeySpec = new X509EncodedKeySpec(decodedBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(encodedPublicKeySpec);

            return Key.builder()
                      .modulus(rsaPublicKey.getModulus())
                      .exponent(rsaPublicKey.getPublicExponent())
                      .build();
        } catch (NoSuchAlgorithmException ignore) {
            // This shouldn't happen but we have to handle it anyways.
            ignore.printStackTrace();
            throw new RuntimeException(ignore);
        }
    }
}
