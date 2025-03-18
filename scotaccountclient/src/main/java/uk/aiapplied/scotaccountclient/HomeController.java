package uk.aiapplied.scotaccountclient;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

/**
 * Controller handling the home page and user authentication status.
 * Provides endpoints for displaying the main application interface.
 */
@Controller
public class HomeController {
    /** Logger instance for this class */
    private static final Logger logger = LoggerFactory.getLogger(HomeController.class);
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final AttributeService attributeService;

    public HomeController(OAuth2AuthorizedClientService authorizedClientService, AttributeService attributeService) {
        this.authorizedClientService = authorizedClientService;
        this.attributeService = attributeService;
    }

    /**
     * Handles requests to the home page.
     *
     * @param model The Spring MVC model for view rendering
     * @param request The HTTP request
     * @return The view name to render
     */
    @GetMapping("/")
    public String home(Model model, HttpServletRequest request) {
        Authentication authentication = (Authentication) request.getUserPrincipal();
        
        if (authentication != null && authentication.isAuthenticated() && authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                oauthToken.getAuthorizedClientRegistrationId(),
                oauthToken.getName()
            );

            if (client != null) {
                OAuth2AccessToken accessToken = client.getAccessToken();
                Map<String, Object> attributes = attributeService.fetchAttributes(accessToken.getTokenValue());
                
                if (attributes != null) {
                    model.addAttribute("verifiedClaims", attributes.get("verified_claims"));
                }
            }
            
            logger.info("User is authenticated: {}", authentication.getName());
        } else {
            logger.info("No authenticated user");
        }
        
        return "home";
    }
}
