package uk.aiapplied.scotaccountclient;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Configuration class for JWT-related beans and settings.
 * Provides beans for JWT decoding and validation.
 */
@Configuration
public class JwtConfig {

    /**
     * Creates an RSAPublicKey bean by loading the public key from the classpath.
     *
     * @return The RSA public key for JWT validation
     * @throws Exception if the key cannot be loaded or parsed
     */
    @Bean
    public RSAPublicKey publicKey() throws Exception {
        ClassPathResource resource = new ClassPathResource("keys/public.pem");
        String key = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * Creates a JwtDecoder bean configured with the RSA public key.
     *
     * @param publicKey The RSA public key for JWT validation
     * @return A configured JwtDecoder instance
     */
    @Bean
    public JwtDecoder jwtDecoder(RSAPublicKey publicKey) {
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }
}