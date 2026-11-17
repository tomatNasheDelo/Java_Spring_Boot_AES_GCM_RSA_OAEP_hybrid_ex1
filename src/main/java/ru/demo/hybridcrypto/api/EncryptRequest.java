package ru.demo.hybridcrypto.api;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record EncryptRequest(
        @NotNull(message = "plaintext is required")
        @Size(max = 1000000, message = "plaintext must be at most 1,000,000 characters")
        String plaintext
) {
}
