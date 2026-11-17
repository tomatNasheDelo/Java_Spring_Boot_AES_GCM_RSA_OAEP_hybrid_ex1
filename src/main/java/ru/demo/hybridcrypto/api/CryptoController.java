package ru.demo.hybridcrypto.api;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.demo.hybridcrypto.service.HybridEncryptionService;
import ru.demo.hybridcrypto.service.HybridEncryptionService.EncryptedEnvelope;

@RestController
@RequestMapping("/api/crypto")
public class CryptoController {
    private final HybridEncryptionService encryptionService;

    public CryptoController(HybridEncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    @PostMapping("/encrypt")
    public EncryptResponse encrypt(@Valid @RequestBody EncryptRequest request) {
        EncryptedEnvelope envelope = encryptionService.encrypt(request.plaintext());
        return new EncryptResponse(envelope.version(), envelope.encryptedKey(), envelope.nonce(), envelope.ciphertext());
    }

    @PostMapping("/decrypt")
    public DecryptResponse decrypt(@Valid @RequestBody DecryptRequest request) {
        String plaintext = encryptionService.decrypt(request.version(), request.encryptedKey(),
                request.nonce(), request.ciphertext());
        return new DecryptResponse(plaintext);
    }
}
