package ru.demo.hybridcrypto.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class RsaKeyConfig {
    @Bean
    public KeyPair rsaKeyPair(
            @Value("${app.crypto.public-key-pem:}") String publicKeyPem,
            @Value("${app.crypto.private-key-pem:}") String privateKeyPem
    ) {
        if (publicKeyPem.isBlank() || privateKeyPem.isBlank()) {
            throw new IllegalStateException("Set RSA_PUBLIC_KEY_PEM and RSA_PRIVATE_KEY_PEM environment variables");
        }
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(decodePem(publicKeyPem)));
            PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(decodePem(privateKeyPem)));
            if (!(publicKey instanceof java.security.interfaces.RSAPublicKey rsaPublic)
                    || !(privateKey instanceof java.security.interfaces.RSAPrivateKey rsaPrivate)
                    || rsaPublic.getModulus().bitLength() < 2048
                    || !rsaPublic.getModulus().equals(rsaPrivate.getModulus())) {
                throw new IllegalArgumentException("RSA key pair must match and use a key size of at least 2048 bits");
            }
            return new KeyPair(publicKey, privateKey);
        } catch (Exception exception) {
            throw new IllegalStateException("Invalid RSA keys; provide a matching X.509 public key and PKCS#8 private key", exception);
        }
    }

    private byte[] decodePem(String pem) {
        String base64 = pem
                .replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(base64);
    }
}
