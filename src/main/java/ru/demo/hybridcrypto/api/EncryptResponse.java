package ru.demo.hybridcrypto.api;

public record EncryptResponse(String version, String encryptedKey, String nonce, String ciphertext) {
}
