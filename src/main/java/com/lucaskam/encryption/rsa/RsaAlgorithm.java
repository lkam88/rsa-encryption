package com.lucaskam.encryption.rsa;

import com.lucaskam.encryption.rsa.models.Key;
import com.lucaskam.encryption.rsa.models.KeyPair;

import java.math.BigInteger;

public class RsaAlgorithm {

    public static final BigInteger ONE = new BigInteger("1");

    private RandomNumberGenerator randomNumberGenerator;

    public RsaAlgorithm(RandomNumberGenerator randomNumberGenerator) {
        this.randomNumberGenerator = randomNumberGenerator;
    }

    /**
     * Generates a 512 Bit RSA private and public key pair
     *
     * @return A pair of keys of private and public keys that contain the modulus and exponent needed for encrypting and decrypting messages.
     */
    public KeyPair generatePublicAndPrivateKey() {
        BigInteger p = randomNumberGenerator.randomPrimeNumber();
        BigInteger q = randomNumberGenerator.randomPrimeNumber();

        BigInteger modulus = p.multiply(q);
        BigInteger totient = leastCommonMultiplier(p.subtract(ONE), q.subtract(ONE));

        BigInteger publicKeyExponent = randomNumberGenerator.chooseRandomCoPrime(totient);
        BigInteger privateKeyExponent = publicKeyExponent.modInverse(totient);

        Key privateKey = Key.builder()
                            .modulus(modulus)
                            .exponent(privateKeyExponent)
                            .build();

        Key publicKey = Key.builder()
                           .modulus(modulus)
                           .exponent(publicKeyExponent)
                           .build();

        return KeyPair.builder()
                      .privateKey(privateKey)
                      .publicKey(publicKey)
                      .build();
    }

    /**
     * Takes an unencrypted message represent as an integer and a public key to encrypt the message.
     *
     * @param unencryptedMessage Message to be encrypted.
     * @param publicKey          The public key that is paired with the private key of the intended recipient of the encrypted message.
     */
    public BigInteger encrypt(BigInteger unencryptedMessage, Key publicKey) {
        return unencryptedMessage.modPow(publicKey.getExponent(), publicKey.getModulus());
    }

    /**
     * Takes an encrypted message represented as an integer and a private key to decrypt the message to its original form.
     *
     * @param encryptedMessage Message that was encrypted using a public key.
     * @param privateKey       The private key that is paired with the public key that encrypted the encryptedMessage.
     */
    public BigInteger decrypt(BigInteger encryptedMessage, Key privateKey) {
        return encryptedMessage.modPow(privateKey.getExponent(), privateKey.getModulus());
    }

    private BigInteger leastCommonMultiplier(BigInteger a, BigInteger b) {
        return a.multiply(b.divide(a.gcd(b)));
    }
}
