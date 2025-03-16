package uk.aiapplied.scotaccount.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;
import java.util.Map;
import java.util.List;
import java.util.HashMap;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for handling JWT operations in the ScotAccount client
 * application.
 * This class provides functionality for:
 * <ul>
 * <li>Loading and managing RSA keys for JWT signing and validation</li>
 * <li>Generating client assertion JWTs for OAuth2 authentication</li>
 * <li>Validating JWTs using public keys from ScotAccount's JWKS endpoint</li>
 * <li>Caching public keys to improve performance</li>
 * </ul>
 * 
 * Key features:
 * <ul>
 * <li>Automatic JWKS key rotation handling</li>
 * <li>Public key caching to reduce JWKS endpoint calls</li>
 * <li>Support for RSA-256 signing algorithm</li>
 * <li>Proper key format handling (PKCS#8 for private, X.509 for public)</li>
 * </ul>
 * 
 * Usage example:
 * 
 * <pre>
 * JwtUtil jwtUtil = new JwtUtil();
 * String clientAssertion = jwtUtil.createClientAssertion(
 *         "client-id",
 *         "https://token-endpoint");
 * </pre>
 */
@Component
public class JwtUtil {
    private static final String PRIVATE_KEY_PATH = "keys/private.pem";
    private static final String JWKS_URL = "https://authz.integration.scotaccount.service.gov.scot/jwks.json";
    private final RestTemplate restTemplate;
    private PrivateKey privateKey;
    private Map<String, PublicKey> publicKeyCache = new HashMap<>();

    public JwtUtil() {
        this.restTemplate = new RestTemplate();
    }

    /**
     * Decodes a Base64URL-encoded string to a BigInteger.
     * Used for converting JWK components (n, e) to their BigInteger
     * representations.
     *
     * @param base64Url The Base64URL-encoded string to decode
     * @return The decoded value as a BigInteger
     * @throws IllegalArgumentException if the input is not valid Base64URL
     */
    private BigInteger base64UrlToBigInteger(String base64Url) {
        byte[] decoded = Base64.getUrlDecoder().decode(base64Url);
        return new BigInteger(1, decoded);
    }

    /**
     * Loads a public key from JWKS for a specific key ID
     */
    private PublicKey loadPublicKeyFromJwks(String keyId) throws Exception {
        // Check cache first
        if (publicKeyCache.containsKey(keyId)) {
            return publicKeyCache.get(keyId);
        }

        ResponseEntity<Map> response = restTemplate.getForEntity(JWKS_URL, Map.class);
        List<Map<String, String>> keys = (List<Map<String, String>>) response.getBody().get("keys");

        for (Map<String, String> key : keys) {
            if (keyId.equals(key.get("kid"))) {
                // Convert JWK parameters to RSA public key
                BigInteger modulus = base64UrlToBigInteger(key.get("n"));
                BigInteger exponent = base64UrlToBigInteger(key.get("e"));

                RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
                KeyFactory factory = KeyFactory.getInstance("RSA");
                PublicKey publicKey = factory.generatePublic(spec);

                // Cache the key
                publicKeyCache.put(keyId, publicKey);
                return publicKey;
            }
        }
        throw new IllegalArgumentException("No matching key found for kid: " + keyId);
    }

    /**
     * Loads the RSA private key from the configured path.
     *
     * @return The loaded PrivateKey instance
     * @throws IOException              if the key file cannot be read
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     * @throws InvalidKeySpecException  if the key format is invalid
     */
    public PrivateKey loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (privateKey != null) {
            return privateKey;
        }

        try (InputStream is = getClass().getClassLoader().getResourceAsStream(PRIVATE_KEY_PATH)) {
            if (is == null) {
                throw new IOException("Private key file not found: " + PRIVATE_KEY_PATH);
            }
            String privateKeyPEM = new String(is.readAllBytes())
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            privateKey = keyFactory.generatePrivate(keySpec);
            return privateKey;
        }
    }

    /**
     * Creates a JWT with the specified claims and expiration time.
     *
     * @param claims       The claims to include in the JWT
     * @param expirationMs The expiration time in milliseconds
     * @return The generated JWT string
     * @throws Exception if token creation fails
     */
    public String createJwt(Claims claims, long expirationMs) throws Exception {
        PrivateKey privateKey = loadPrivateKey();
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    /**
     * Creates a client assertion JWT for OAuth2 authentication.
     *
     * @param clientId      The OAuth2 client ID
     * @param tokenEndpoint The OAuth2 token endpoint URL
     * @return The generated client assertion JWT
     * @throws Exception if token creation fails
     */
    public String createClientAssertion(String clientId, String tokenEndpoint) throws Exception {
        Claims claims = Jwts.claims()
                .setIssuer(clientId)
                .setSubject(clientId)
                .setAudience(tokenEndpoint)
                .setId(UUID.randomUUID().toString());

        // Calculate 6 months in milliseconds
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, 6);
        long expirationMs = calendar.getTimeInMillis() - System.currentTimeMillis();

        return createJwt(claims, expirationMs);
    }

    /**
     * Extracts the key ID from a JWT header
     */
    private String extractKeyId(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format");
        }

        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        try {
            Map<String, String> header = new ObjectMapper().readValue(headerJson, Map.class);
            String kid = header.get("kid");
            if (kid == null) {
                throw new IllegalArgumentException("No 'kid' found in JWT header");
            }
            return kid;
        } catch (Exception e) {
            throw new RuntimeException("Error parsing JWT header", e);
        }
    }

    /**
     * Validates a JWT and returns its claims.
     *
     * @param jwt The JWT to validate
     * @return The claims from the validated JWT
     * @throws Exception if the JWT is invalid
     */
    public Claims validateJwt(String jwt) throws Exception {
        String keyId = extractKeyId(jwt);
        PublicKey publicKey = loadPublicKeyFromJwks(keyId);

        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }
}