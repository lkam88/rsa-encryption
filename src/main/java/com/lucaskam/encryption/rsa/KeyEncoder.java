package com.lucaskam.encryption.rsa;

import com.lucaskam.encryption.rsa.models.Key;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyEncoder {

    /**
     * Takes a private key with a modulus and exponent and encodes those numbers into a Base64 String.
     *
     * @param privateKey Private key to be encoded.
     * @return A Base 64 encoded representation of the passed private key.
     * @throws InvalidKeySpecException This exception represents a private key that does not conform to the RSA specification.
     */
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

    /**
     * Takes a public key with a modulus and exponent and encodes those numbers into a Base64 String.
     *
     * @param publicKey Public key to be encoded.
     * @return A Base 64 encoded representation of the passed public key.
     * @throws InvalidKeySpecException This exception represents a private key that does not conform to the RSA specification.
     */
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

    /**
     * Takes a private key represented as a Base64 encoded String and returns a Key containing the private key's modulus and exponent.
     *
     * @param encodedPrivateKey A Base 64 encoded representation of a private key to be decoded.
     * @return A Base 64 encoded representation of the passed private key.
     * @throws InvalidKeySpecException This exception represents a private key that does not conform to the RSA specification.
     */
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
