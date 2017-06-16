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

    public BigInteger decrypt(BigInteger encryptedMessage, Key privateKey) {
        return encryptedMessage.pow(privateKey.getExponent().intValue()).mod(privateKey.getModulus());
    }

    public BigInteger encrypt(BigInteger unencryptedMessage, Key publicKey) {
        return unencryptedMessage.pow(publicKey.getExponent().intValue()).mod(publicKey.getModulus());
    }

    private BigInteger leastCommonMultiplier(BigInteger a, BigInteger b) {
        return a.multiply(b.divide(a.gcd(b)));
    }
}
