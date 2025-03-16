package uk.aiapplied.scotaccountclient;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.ui.Model;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@link HomeController} class.
 * Tests the handling of authenticated and unauthenticated users,
 * as well as error scenarios in the home page controller.
 */
@ExtendWith(MockitoExtension.class)
class HomeControllerTest {

    private HomeController homeController;

    @Mock
    private Model model;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpSession session;

    @Mock
    private OidcUser oidcUser;

    @Mock
    private Authentication authentication;

    @Mock
    private SecurityContext securityContext;

    /**
     * Sets up the test environment before each test.
     * Initializes the HomeController and configures basic mock behavior.
     */
    @BeforeEach
    void setUp() {
        homeController = new HomeController();
        when(request.getSession()).thenReturn(session);
        SecurityContextHolder.setContext(securityContext);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Tests the home page behavior when no user is authenticated.
     * Verifies that the model is properly configured for an unauthenticated user.
     */
    @Test
    void home_WhenUserNotAuthenticated_ShouldSetAuthenticatedFalse() {
        // Given
        when(session.getAttribute(anyString())).thenReturn(null);
        when(securityContext.getAuthentication()).thenReturn(null);

        // When
        String viewName = homeController.home(model, request);

        // Then
        verify(model).addAttribute("authenticated", false);
        assertEquals("home", viewName);
    }

    /**
     * Tests the home page behavior when a user is authenticated.
     * Verifies that user information, tokens, and claims are properly set in the model.
     * This test simulates a successful OAuth2/OIDC authentication scenario.
     */
    @Test
    void home_WhenUserAuthenticated_ShouldSetUserAttributes() {
        // Given
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user123");
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), 
            Instant.now().plusSeconds(3600), claims);
        
        when(oidcUser.getSubject()).thenReturn("user123");
        when(oidcUser.getUserInfo()).thenReturn(null);
        when(oidcUser.getIdToken()).thenReturn(idToken);
        when(authentication.getPrincipal()).thenReturn(oidcUser);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        
        // Mock all possible session attributes
        when(session.getAttribute(anyString())).thenReturn(null); // Default behavior
        when(session.getAttribute("token_claims")).thenReturn(claims);
        when(session.getAttribute("access_token")).thenReturn("access-token");
        when(session.getAttribute("auth_error")).thenReturn(null);
        when(session.getAttribute("auth_error_type")).thenReturn(null);
        when(session.getAttribute("token_error")).thenReturn(null);

        // When
        String viewName = homeController.home(model, request);

        // Then
        verify(model).addAttribute("authenticated", true);
        verify(model).addAttribute("userInfo", null);
        verify(model).addAttribute("idToken", "token");
        verify(model).addAttribute("tokenClaims", claims);
        verify(model).addAttribute("accessToken", "access-token");
        assertEquals("home", viewName);
    }

    /**
     * Tests the handling of authentication errors in the home page.
     * Verifies that error messages are properly retrieved from the session,
     * added to the model, and then cleared from the session.
     */
    @Test
    void home_WhenAuthenticationError_ShouldSetErrorAttributes() {
        // Given
        when(session.getAttribute("auth_error")).thenReturn("Auth Failed");
        when(session.getAttribute("auth_error_type")).thenReturn("AuthError");
        when(session.getAttribute("token_error")).thenReturn("Token Invalid");
        when(securityContext.getAuthentication()).thenReturn(null);

        // When
        String viewName = homeController.home(model, request);

        // Then
        verify(model).addAttribute("error", true);
        verify(model).addAttribute("errorMessage", "Auth Failed");
        verify(model).addAttribute("errorType", "AuthError");
        verify(model).addAttribute("tokenError", "Token Invalid");
        verify(session).removeAttribute("auth_error");
        verify(session).removeAttribute("auth_error_type");
        verify(session).removeAttribute("token_error");
        assertEquals("home", viewName);
    }
} 