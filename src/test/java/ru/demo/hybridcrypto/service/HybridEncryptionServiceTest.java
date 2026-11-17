package ru.demo.hybridcrypto.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HybridEncryptionServiceTest {
    private HybridEncryptionService service;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        service = new HybridEncryptionService(generator.generateKeyPair());
    }

    @Test
    void encryptThenDecryptRestoresUnicodePlaintext() {
        String plaintext = "Гибридное шифрование 🔐: AES-GCM + RSA-OAEP";

        HybridEncryptionService.EncryptedEnvelope envelope = service.encrypt(plaintext);

        assertEquals(HybridEncryptionService.VERSION, envelope.version());
        assertEquals(plaintext, service.decrypt(envelope.version(), envelope.encryptedKey(),
                envelope.nonce(), envelope.ciphertext()));
    }

    @Test
    void repeatedEncryptionUsesDifferentKeyNonceAndCiphertext() {
        HybridEncryptionService.EncryptedEnvelope first = service.encrypt("same input");
        HybridEncryptionService.EncryptedEnvelope second = service.encrypt("same input");

        assertNotEquals(first.encryptedKey(), second.encryptedKey());
        assertNotEquals(first.nonce(), second.nonce());
        assertNotEquals(first.ciphertext(), second.ciphertext());
    }

    @Test
    void modifiedCiphertextFailsAuthentication() {
        HybridEncryptionService.EncryptedEnvelope envelope = service.encrypt("confidential");
        byte[] ciphertext = java.util.Base64.getDecoder().decode(envelope.ciphertext());
        ciphertext[0] ^= 1;

        assertThrows(CryptoOperationException.class, () -> service.decrypt(envelope.version(),
                envelope.encryptedKey(), envelope.nonce(), java.util.Base64.getEncoder().encodeToString(ciphertext)));
    }

    @Test
    void rejectsUnsupportedFormatVersion() {
        assertThrows(CryptoOperationException.class,
                () -> service.decrypt("v2", "key", "nonce", "ciphertext"));
    }
}
