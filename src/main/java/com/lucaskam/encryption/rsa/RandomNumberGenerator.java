package com.lucaskam.encryption.rsa;

import java.math.BigInteger;
import java.util.Random;

public class RandomNumberGenerator {
    public static final int BIT_LENGTH = 512;
    private Random random;

    public RandomNumberGenerator(Random random) {
        this.random = random;
    }

    public BigInteger randomPrimeNumber() {
        return BigInteger.probablePrime(BIT_LENGTH, random);
    }

    public BigInteger chooseRandomCoPrime(BigInteger totient) {
        BigInteger coPrime;
        do {
            coPrime = new BigInteger(2 * BIT_LENGTH, random);
        }
        while ((coPrime.compareTo(totient) != -1) || (coPrime.gcd(totient).compareTo(BigInteger.valueOf(1)) != 0));

        return coPrime;
    }
}
