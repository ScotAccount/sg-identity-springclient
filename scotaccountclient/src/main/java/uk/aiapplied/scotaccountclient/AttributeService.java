package uk.aiapplied.scotaccountclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;

@Service
public class AttributeService {
    private static final Logger logger = LoggerFactory.getLogger(AttributeService.class);
    private final RestTemplate restTemplate;
    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper;

    @Value("${spring.security.oauth2.client.registration.scotaccount.client-id}")
    private String clientId;

    @Value("${scotaccount.attributes.endpoint}")
    private String attributesEndpoint;

    public AttributeService(RestTemplate restTemplate, JwtUtil jwtUtil, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.jwtUtil = jwtUtil;
        this.objectMapper = objectMapper;
    }

    public Map<String, Object> fetchAttributes(String accessToken) {
        try {
            String clientAssertion = jwtUtil.createClientAssertion(clientId, attributesEndpoint);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + accessToken);
            headers.set("DIS-Client-Assertion", clientAssertion);

            HttpEntity<?> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                attributesEndpoint,
                HttpMethod.GET,
                entity,
                String.class
            );

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> responseMap = objectMapper.readValue(response.getBody(), Map.class);
                String claimsToken = (String) responseMap.get("claimsToken");
                
                // Decode and parse the JWT claims
                String[] parts = claimsToken.split("\\.");
                String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                return objectMapper.readValue(payload, Map.class);
            }

            logger.error("Failed to fetch attributes. Status: {}", response.getStatusCode());
            return null;
        } catch (Exception e) {
            logger.error("Error fetching attributes", e);
            return null;
        }
    }
} 