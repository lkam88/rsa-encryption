package com.lucaskam.encryption.rsa;

import com.lucaskam.encryption.rsa.models.Key;
import com.lucaskam.encryption.rsa.models.KeyPair;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.math.BigInteger;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

public class RsaAlgorithmTest {
    private RsaAlgorithm rsaAlgorithm;
    
    private RandomNumberGenerator mockRng;

    @Before
    public void setUp() throws Exception {
        mockRng = Mockito.mock(RandomNumberGenerator.class);
        rsaAlgorithm = new RsaAlgorithm(mockRng);
    }

    @Test
    public void testGeneratePublicAndPrivateKey() throws Exception {
        when(mockRng.randomPrimeNumber()).thenReturn(new BigInteger("61"), new BigInteger("53"));
        when(mockRng.chooseRandomCoPrime(any(BigInteger.class))).thenReturn(new BigInteger("17"));

        KeyPair keyPair = rsaAlgorithm.generatePublicAndPrivateKey();
        Key privateKey = keyPair.getPrivateKey();
        Key publicKey = keyPair.getPublicKey();
        
        assertEquals(new BigInteger("3233"), privateKey.getModulus());
        assertEquals(new BigInteger("413"), privateKey.getExponent());
        assertEquals(new BigInteger("3233"), publicKey.getModulus());
        assertEquals(new BigInteger("17"), publicKey.getExponent());
    }

    @Test
    public void testEncrypt() throws Exception {
        BigInteger unencryptedMessage = new BigInteger("65");
        BigInteger publicModulus = new BigInteger("3233");
        BigInteger publicExponent = new BigInteger("17");
        Key publicKey = Key.builder()
            .modulus(publicModulus)
            .exponent(publicExponent)
            .build();
        
        BigInteger encryptedMessage = rsaAlgorithm.encrypt(unencryptedMessage, publicKey);
        
        assertEquals(new BigInteger("2790"), encryptedMessage);
    }

    @Test
    public void testDecrypt() throws Exception {
        BigInteger encryptedMessage2 = new BigInteger("2790");
        BigInteger privateModulus = new BigInteger("3233");
        BigInteger privateExponent = new BigInteger("413");
        Key privateKey = Key.builder()
                           .modulus(privateModulus)
                           .exponent(privateExponent)
                           .build();

        BigInteger unencryptedMessage = rsaAlgorithm.encrypt(encryptedMessage2, privateKey);

        assertEquals(new BigInteger("65"), unencryptedMessage);
    }
}