package ru.demo.hybridcrypto.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class HybridCryptoApiIntegrationTest {
    private static final KeyPair TEST_KEY_PAIR = createKeyPair();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @org.springframework.test.context.DynamicPropertySource
    static void rsaKeys(org.springframework.test.context.DynamicPropertyRegistry registry) {
        registry.add("app.crypto.public-key-pem", () -> Base64.getEncoder().encodeToString(TEST_KEY_PAIR.getPublic().getEncoded()));
        registry.add("app.crypto.private-key-pem", () -> Base64.getEncoder().encodeToString(TEST_KEY_PAIR.getPrivate().getEncoded()));
    }

    @Test
    void encryptAndDecryptThroughHttpApi() throws Exception {
        String encryptedJson = mockMvc.perform(post("/api/crypto/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"plaintext":"hello hybrid crypto"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value("v1"))
                .andExpect(jsonPath("$.encryptedKey").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        JsonNode envelope = objectMapper.readTree(encryptedJson);
        String decryptRequest = objectMapper.createObjectNode()
                .put("version", envelope.get("version").asText())
                .put("encryptedKey", envelope.get("encryptedKey").asText())
                .put("nonce", envelope.get("nonce").asText())
                .put("ciphertext", envelope.get("ciphertext").asText())
                .toString();

        mockMvc.perform(post("/api/crypto/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(decryptRequest))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.plaintext").value("hello hybrid crypto"));
    }

    @Test
    void rejectsInvalidInputAndTamperedPayload() throws Exception {
        mockMvc.perform(post("/api/crypto/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""{"plaintext":" "}"""))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/crypto/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"version":"v1","encryptedKey":"bad","nonce":"bad","ciphertext":"bad"}
                                """))
                .andExpect(status().isBadRequest());
    }

    private static KeyPair createKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }
}
