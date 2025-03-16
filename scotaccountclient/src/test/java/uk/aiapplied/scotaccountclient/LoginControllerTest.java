package uk.aiapplied.scotaccountclient;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link LoggedInController} class.
 * Tests the OAuth2/OIDC authentication success and failure scenarios,
 * including token processing, error handling, and session management.
 */
@ExtendWith(MockitoExtension.class)
class LoginControllerTest {

    private LoginController loginController;

    @Mock
    private OAuth2AuthorizedClientService authorizedClientService;

    @Mock
    private JwtDecoder jwtDecoder;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @Mock
    private OAuth2AuthenticationToken oauth2Auth;

    @Mock
    private OAuth2AuthorizedClient authorizedClient;

    @Mock
    private OidcUser oidcUser;

    @Mock
    private OAuth2AccessToken accessToken;

    @Mock
    private Jwt jwt;

    /**
     * Sets up the test environment before each test.
     * Initializes the LoggedInController with mocked dependencies and
     * configures basic mock behavior.
     */
    @BeforeEach
    void setUp() {
        loginController = new LoginController(authorizedClientService, jwtDecoder);
        when(request.getSession()).thenReturn(session);
    }

    /**
     * Tests successful authentication with valid OAuth2 tokens.
     * Verifies that access tokens and ID tokens are properly processed,
     * decoded, and stored in the session.
     *
     * @throws Exception if any error occurs during the test
     */
    @Test
    void onAuthenticationSuccess_WhenValidOAuth2Token_ShouldProcessTokens() throws Exception {
        // Given
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user123");
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(),
                Instant.now().plusSeconds(3600), claims);

        when(oauth2Auth.getAuthorizedClientRegistrationId()).thenReturn("scotaccount");
        when(oauth2Auth.getName()).thenReturn("user123");
        when(oauth2Auth.getPrincipal()).thenReturn(oidcUser);
        when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
                .thenReturn(authorizedClient);
        when(authorizedClient.getAccessToken()).thenReturn(accessToken);
        when(accessToken.getTokenValue()).thenReturn("access-token");
        when(jwtDecoder.decode(anyString())).thenReturn(jwt);
        when(jwt.getClaims()).thenReturn(claims);
        when(oidcUser.getIdToken()).thenReturn(idToken);

        // When
        loginController.onAuthenticationSuccess(request, response, oauth2Auth);

        // Then
        verify(session).setAttribute("access_token", "access-token");
        verify(session).setAttribute("access_token_claims", claims);
        verify(session).setAttribute("id_token", "token");
        verify(response).sendRedirect("/");
    }

    /**
     * Tests the scenario where token decoding fails.
     * Verifies that appropriate error information is stored in the session
     * and the user is redirected to the home page.
     *
     * @throws Exception if any error occurs during the test
     */
    @Test
    void onAuthenticationSuccess_WhenTokenDecodingFails_ShouldHandleError() throws Exception {
        // Given
        when(oauth2Auth.getAuthorizedClientRegistrationId()).thenReturn("scotaccount");
        when(oauth2Auth.getName()).thenReturn("user123");
        when(oauth2Auth.getPrincipal()).thenReturn(oidcUser);
        when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
                .thenReturn(authorizedClient);
        when(authorizedClient.getAccessToken()).thenReturn(accessToken);
        when(accessToken.getTokenValue()).thenReturn("access-token");
        when(jwtDecoder.decode(anyString())).thenThrow(new RuntimeException("Invalid token"));

        // When
        loginController.onAuthenticationSuccess(request, response, oauth2Auth);

        // Then
        verify(session).setAttribute("token_error", "Access token error: Invalid token");
        verify(response).sendRedirect("/");
    }

    /**
     * Tests authentication failure handling.
     * Verifies that error details are properly stored in the session
     * and the user is redirected with appropriate error parameters.
     *
     * @throws Exception if any error occurs during the test
     */
    @Test
    void onAuthenticationFailure_ShouldSetErrorAttributesAndRedirect() throws Exception {
        // Arrange
        AuthenticationException authException = mock(AuthenticationException.class);
        when(authException.getMessage()).thenReturn("AuthError");
        when(request.getSession()).thenReturn(session);
        when(request.getRequestURI()).thenReturn("/oauth2/authorization/scotaccount");
        when(request.getQueryString()).thenReturn("error=invalid_request");

        // Act
        loginController.onAuthenticationFailure(request, response, authException);

        // Verify
        verify(session).setAttribute("auth_error", "AuthError");
        verify(session).setAttribute("auth_error_type", authException.getClass().getSimpleName());
        verify(response).sendRedirect(contains("/?error=true&message=AuthError"));
    }

    /**
     * Tests the scenario where no authorized client is found.
     * Verifies that appropriate error information is stored in the session
     * when the OAuth2 authorized client cannot be loaded.
     *
     * @throws Exception if any error occurs during the test
     */
    @Test
    void onAuthenticationSuccess_WhenNoAuthorizedClient_ShouldHandleError() throws Exception {
        // Given
        when(oauth2Auth.getAuthorizedClientRegistrationId()).thenReturn("scotaccount");
        when(oauth2Auth.getName()).thenReturn("user123");
        when(oauth2Auth.getPrincipal()).thenReturn(oidcUser);
        when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
                .thenReturn(null);

        // When
        loginController.onAuthenticationSuccess(request, response, oauth2Auth);

        // Then
        verify(session).setAttribute("token_error", "No authorized client found");
        verify(response).sendRedirect("/");
    }
}