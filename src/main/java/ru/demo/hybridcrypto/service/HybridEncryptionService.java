package ru.demo.hybridcrypto.service;

import org.springframework.stereotype.Service;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

@Service
public class HybridEncryptionService {
    public static final String VERSION = "v1";
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPPadding";
    private static final int AES_KEY_BITS = 256;
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final byte[] AAD = VERSION.getBytes(StandardCharsets.UTF_8);
    private static final OAEPParameterSpec OAEP_PARAMETERS = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private final KeyPair rsaKeyPair;
    private final SecureRandom secureRandom;

    public HybridEncryptionService(KeyPair rsaKeyPair) {
        this(rsaKeyPair, new SecureRandom());
    }

    HybridEncryptionService(KeyPair rsaKeyPair, SecureRandom secureRandom) {
        this.rsaKeyPair = rsaKeyPair;
        this.secureRandom = secureRandom;
    }

    public EncryptedEnvelope encrypt(String plaintext) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(AES_KEY_BITS, secureRandom);
            SecretKey aesKey = keyGenerator.generateKey();

            byte[] nonce = new byte[GCM_NONCE_BYTES];
            secureRandom.nextBytes(nonce);

            Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            aesCipher.updateAAD(AAD);
            byte[] encryptedData = aesCipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
            rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic(), OAEP_PARAMETERS, secureRandom);
            byte[] encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());

            Base64.Encoder encoder = Base64.getEncoder();
            return new EncryptedEnvelope(VERSION, encoder.encodeToString(encryptedKey),
                    encoder.encodeToString(nonce), encoder.encodeToString(encryptedData));
        } catch (GeneralSecurityException exception) {
            throw new CryptoOperationException("Encryption failed", exception);
        }
    }

    public String decrypt(String version, String encodedEncryptedKey, String encodedNonce, String encodedCiphertext) {
        if (!VERSION.equals(version)) {
            throw new CryptoOperationException("Unsupported encrypted payload version");
        }
        try {
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] encryptedKey = decoder.decode(encodedEncryptedKey);
            byte[] nonce = decoder.decode(encodedNonce);
            byte[] ciphertext = decoder.decode(encodedCiphertext);
            if (nonce.length != GCM_NONCE_BYTES || ciphertext.length < GCM_TAG_BITS / Byte.SIZE) {
                throw new CryptoOperationException("Invalid encrypted payload");
            }

            Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate(), OAEP_PARAMETERS);
            byte[] rawAesKey = rsaCipher.doFinal(encryptedKey);
            if (rawAesKey.length != AES_KEY_BITS / Byte.SIZE) {
                throw new CryptoOperationException("Invalid encrypted payload");
            }
            SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(rawAesKey, "AES");

            Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            aesCipher.updateAAD(AAD);
            return new String(aesCipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (AEADBadTagException exception) {
            throw new CryptoOperationException("Encrypted payload authentication failed", exception);
        } catch (IllegalArgumentException exception) {
            throw new CryptoOperationException("Encrypted payload is invalid Base64", exception);
        } catch (GeneralSecurityException exception) {
            throw new CryptoOperationException("Encrypted payload could not be decrypted", exception);
        }
    }

    public record EncryptedEnvelope(String version, String encryptedKey, String nonce, String ciphertext) {
    }
}
