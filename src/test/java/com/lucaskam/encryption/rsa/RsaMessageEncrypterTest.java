package com.lucaskam.encryption.rsa;

import com.lucaskam.encryption.rsa.models.Key;
import com.lucaskam.encryption.rsa.models.KeyPair;
import com.lucaskam.encryption.rsa.models.Response;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.math.BigInteger;

import static junit.framework.TestCase.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RsaMessageEncrypterTest {
    
    private RsaMessageEncrypter rsaMessageEncrypter;
    
    private KeyEncoder keyEncoder;
    private MessageEncoder messageEncoder;
    private RsaAlgorithm rsaAlgorithm;
    private KeyStore keyStore;
 
    @Before
    public void setUp() throws Exception {
        rsaAlgorithm = mock(RsaAlgorithm.class);
        keyEncoder = mock(KeyEncoder.class);
        messageEncoder = mock(MessageEncoder.class);
        keyStore = mock(KeyStore.class);
        
        rsaMessageEncrypter = new RsaMessageEncrypter(rsaAlgorithm, keyEncoder, messageEncoder, keyStore);
    }
    
    @Test
    public void testEncryptMessage_KeysAlreadyGenerated() throws Exception {
        String testMessage = "testMessage";
        
        KeyPair keyPair = mock(KeyPair.class);
        Key publicKey = mock(Key.class);
        when(keyPair.getPublicKey()).thenReturn(publicKey);

        BigInteger encryptedMessage = mock(BigInteger.class);
        
        when(keyStore.keysGenerated()).thenReturn(true);
        when(keyStore.readKeys()).thenReturn(keyPair);
        
        when(keyEncoder.encodePublicKey(publicKey)).thenReturn("encodedPublicKey");

        when(rsaAlgorithm.encrypt(any(BigInteger.class), eq(publicKey))).thenReturn(encryptedMessage);
        when(messageEncoder.encodeEncryptedMessage(encryptedMessage)).thenReturn("encryptedSignature");
        
        Response response = rsaMessageEncrypter.encryptMessage(testMessage);
        assertEquals(testMessage, response.getMessage());
        assertEquals("encryptedSignature", response.getSignature());
        assertEquals("-----BEGIN PUBLIC KEY-----\nencodedPublicKey\n-----END PUBLIC KEY-----\n", response.getPubKey());
    }

    @Test
    public void testEncryptMessage_KeysNotGenerated() throws Exception {
        String testMessage = "testMessage";

        KeyPair keyPair = mock(KeyPair.class);
        Key publicKey = mock(Key.class);
        when(keyPair.getPublicKey()).thenReturn(publicKey);

        BigInteger encryptedMessage = mock(BigInteger.class);

        when(keyStore.keysGenerated()).thenReturn(false);
        when(rsaAlgorithm.generatePublicAndPrivateKey()).thenReturn(keyPair);

        when(keyEncoder.encodePublicKey(publicKey)).thenReturn("encodedPublicKey");

        when(rsaAlgorithm.encrypt(any(BigInteger.class), eq(publicKey))).thenReturn(encryptedMessage);
        when(messageEncoder.encodeEncryptedMessage(encryptedMessage)).thenReturn("encryptedSignature");

        Response response = rsaMessageEncrypter.encryptMessage(testMessage);
        assertEquals(testMessage, response.getMessage());
        assertEquals("encryptedSignature", response.getSignature());
        assertEquals("-----BEGIN PUBLIC KEY-----\nencodedPublicKey\n-----END PUBLIC KEY-----\n", response.getPubKey());
        
        verify(keyStore).writeKeys(keyPair);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptMessage_NullMessage() throws Exception {
        rsaMessageEncrypter.encryptMessage(null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testEncryptMessage_EmptyMessage() throws Exception {
        rsaMessageEncrypter.encryptMessage("");
    }

    @Test
    public void testEncryptMessage() throws Exception {
        String testMessage = "testMessage";

        when(keyEncoder.decodePrivateKey(any())).thenCallRealMethod();
        when(keyEncoder.decodePublicKey(any())).thenCallRealMethod();

        Key publicKey = keyEncoder.decodePublicKey(TestKeys.TEST_PUBLIC_KEY);
        Key privateKey = keyEncoder.decodePrivateKey(TestKeys.TEST_PRIVATE_KEY);

        KeyPair keyPair = KeyPair.builder()
                .publicKey(publicKey)
                .privateKey(privateKey)
                .build();
        when(keyEncoder.encodePublicKey(any())).thenCallRealMethod();
        when(keyStore.keysGenerated()).thenReturn(true);
        when(keyStore.readKeys()).thenReturn(keyPair);
        when(rsaAlgorithm.encrypt(any(), any())).thenCallRealMethod();
        when(rsaAlgorithm.decrypt(any(), any())).thenCallRealMethod();
        when(messageEncoder.encodeEncryptedMessage(any())).thenCallRealMethod();
        when(messageEncoder.decodeEncryptedMessage(any())).thenCallRealMethod();

        Response response = rsaMessageEncrypter.encryptMessage(testMessage);

        String result = rsaMessageEncrypter.decryptMessage(response.getSignature());

        assertEquals(testMessage, result);
    }
}