package scot.gov.scotaccountclient;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

@ExtendWith(MockitoExtension.class)
public class AttributeServiceTest {

        @Mock
        private RestTemplate restTemplate;

        @Mock
        private JwtUtil jwtUtil;

        @Mock
        private ObjectMapper mockObjectMapper;

        private AttributeService attributeService;

        @BeforeEach
        void setUp() {
                // Use mock ObjectMapper instead of real one
                attributeService = new AttributeService(restTemplate, jwtUtil, mockObjectMapper);
                ReflectionTestUtils.setField(attributeService, "clientId", "test-client");
                ReflectionTestUtils.setField(attributeService, "attributesEndpoint",
                                "https://api.example.com/attributes");
        }

        @Test
        void fetchAttributes_WhenSuccessful_ShouldReturnAttributes() throws Exception {
                // Given
                String accessToken = "test-access-token";
                String clientAssertion = "test-client-assertion";

                // Prepare mock response data
                Map<String, Object> attributes = new HashMap<>();
                attributes.put("name", "John Doe");
                attributes.put("email", "john@example.com");

                // Mock response containing a JWT
                String responseJson = "{\"claimsToken\":\"header.eyJuYW1lIjoiSm9obiBEb2UiLCJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20ifQ==.signature\"}";

                // Setup mocks
                when(jwtUtil.createClientAssertion(anyString(), anyString())).thenReturn(clientAssertion);

                when(restTemplate.exchange(
                                eq("https://api.example.com/attributes"),
                                eq(HttpMethod.GET),
                                any(HttpEntity.class),
                                eq(String.class))).thenReturn(new ResponseEntity<>(responseJson, HttpStatus.OK));

                // Setup ObjectMapper mocks
                Map<String, String> responseMap = new HashMap<>();
                responseMap.put("claimsToken",
                                "header.eyJuYW1lIjoiSm9obiBEb2UiLCJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20ifQ==.signature");

                when(mockObjectMapper.readValue(anyString(), eq(Map.class)))
                                .thenReturn(responseMap)
                                .thenReturn(attributes); // Second call is for JWT payload

                // Mock the writerWithDefaultPrettyPrinter method
                ObjectWriter mockWriter = mock(ObjectWriter.class);
                when(mockObjectMapper.writerWithDefaultPrettyPrinter()).thenReturn(mockWriter);
                when(mockWriter.writeValueAsString(any())).thenReturn("{}");

                // When
                Map<String, Object> result = attributeService.fetchAttributes(accessToken);

                // Then
                assertNotNull(result);

                // Verify all mocks were called correctly
                verify(jwtUtil).createClientAssertion(eq("test-client"), eq("https://api.example.com/attributes"));
                verify(restTemplate).exchange(
                                eq("https://api.example.com/attributes"),
                                eq(HttpMethod.GET),
                                any(HttpEntity.class),
                                eq(String.class));
                verify(mockObjectMapper, times(2)).readValue(anyString(), eq(Map.class));
                verify(mockObjectMapper, times(2)).writerWithDefaultPrettyPrinter();
                verify(mockWriter, times(2)).writeValueAsString(any());
        }

        @Test
        void fetchAttributes_WhenServerError_ShouldReturnNull() throws Exception {
                // Given
                String accessToken = "test-access-token";
                String clientAssertion = "test-client-assertion";

                when(jwtUtil.createClientAssertion(anyString(), anyString())).thenReturn(clientAssertion);
                doThrow(new HttpClientErrorException(HttpStatus.INTERNAL_SERVER_ERROR))
                                .when(restTemplate).exchange(
                                                anyString(),
                                                eq(HttpMethod.GET),
                                                any(HttpEntity.class),
                                                eq(String.class));

                // When
                Map<String, Object> result = attributeService.fetchAttributes(accessToken);

                // Then
                assertNull(result);

                // Verify mocks were called
                verify(jwtUtil).createClientAssertion(anyString(), anyString());
                verify(restTemplate).exchange(
                                anyString(),
                                eq(HttpMethod.GET),
                                any(HttpEntity.class),
                                eq(String.class));
                // No ObjectMapper calls should happen on error
                verifyNoInteractions(mockObjectMapper);
        }

        @Test
        void fetchAttributes_WhenUnauthorized_ShouldReturnNull() throws Exception {
                // Given
                String accessToken = "test-access-token";
                String clientAssertion = "test-client-assertion";

                when(jwtUtil.createClientAssertion(anyString(), anyString())).thenReturn(clientAssertion);
                doThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED))
                                .when(restTemplate).exchange(
                                                anyString(),
                                                eq(HttpMethod.GET),
                                                any(HttpEntity.class),
                                                eq(String.class));

                // When
                Map<String, Object> result = attributeService.fetchAttributes(accessToken);

                // Then
                assertNull(result);

                // Verify mocks were called
                verify(jwtUtil).createClientAssertion(anyString(), anyString());
                verify(restTemplate).exchange(
                                anyString(),
                                eq(HttpMethod.GET),
                                any(HttpEntity.class),
                                eq(String.class));
                // No ObjectMapper calls should happen on error
                verifyNoInteractions(mockObjectMapper);
        }
}