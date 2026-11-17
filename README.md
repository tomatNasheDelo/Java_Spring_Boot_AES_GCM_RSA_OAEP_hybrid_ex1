# Spring Boot hybrid encryption demo

Educational Java 17 / Spring Boot REST API demonstrating hybrid encryption with JCA: AES-256-GCM encrypts the message; RSA-OAEP (SHA-256, MGF1-SHA-256) encrypts the fresh AES key. This is a learning project, not a production-ready encryption service.

## Start here

See [`start.txt`](start.txt) for key generation, startup, API requests, tests, and important security notes.

## Scheme

1. Generate a fresh random AES-256 key and 96-bit GCM nonce for each encryption.
2. Encrypt the UTF-8 message with AES-GCM and authenticate the format version as AAD.
3. Wrap the AES key using the recipient's RSA public key and explicit OAEP SHA-256/MGF1 SHA-256 parameters.
4. Return a versioned envelope containing the wrapped key, nonce, and ciphertext (all Base64).
5. Decrypt the AES key with the RSA private key, then authenticate and decrypt the payload with AES-GCM.

The private key must remain secret. Anyone with the public key may encrypt to its owner; decryption is possible only with the matching private key.
