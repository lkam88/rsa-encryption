package com.lucaskam.encryption.rsa;

import java.math.BigInteger;
import java.util.Random;

public class RandomNumberGenerator {
    public static final int BIT_LENGTH = 512;
    private Random random;

    public RandomNumberGenerator(Random random) {
        this.random = random;
    }

    /**
     * Generates a random prime number with a 512 bit length.  The number is not guaranteed to be prime, but has an extremely of probability of being a prime
     * number.
     *
     * @return An 512 bit integer that is probably a prime number.
     */
    public BigInteger randomPrimeNumber() {
        return BigInteger.probablePrime(BIT_LENGTH, random);
    }

    /**
     * Chooses a random coprime of the passed integer. *
     *
     * @param number An integer which will be a coprime of the returned integer
     * @return A randomly chosen coprime of the passed integer.
     */
    public BigInteger chooseRandomCoPrime(BigInteger number) {
        BigInteger coPrime;
        do {
            coPrime = new BigInteger(2 * BIT_LENGTH, random);
        }
        while ((coPrime.compareTo(number) != -1) || (coPrime.gcd(number).compareTo(BigInteger.valueOf(1)) != 0));

        return coPrime;
    }
}
