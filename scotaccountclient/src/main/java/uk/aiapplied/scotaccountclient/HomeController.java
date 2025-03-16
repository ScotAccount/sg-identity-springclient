package uk.aiapplied.scotaccountclient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Controller handling the home page and user authentication status.
 * Provides endpoints for displaying the main application interface.
 */
@Controller
public class HomeController {
    /** Logger instance for this class */
    private static final Logger logger = LoggerFactory.getLogger(HomeController.class);

    /**
     * Handles requests to the home page.
     *
     * @param model The Spring MVC model for view rendering
     * @param request The HTTP request
     * @return The view name to render
     */
    @GetMapping("/")
    public String home(Model model, HttpServletRequest request) {
        HttpSession session = request.getSession();

        // Check for authentication errors
        String authError = (String) session.getAttribute("auth_error");
        String authErrorType = (String) session.getAttribute("auth_error_type");
        String tokenError = (String) session.getAttribute("token_error");

        if (authError != null || authErrorType != null || tokenError != null) {
            model.addAttribute("error", true);
            model.addAttribute("errorMessage", authError);
            model.addAttribute("errorType", authErrorType);
            model.addAttribute("tokenError", tokenError);
            // Clear the error attributes after reading them
            session.removeAttribute("auth_error");
            session.removeAttribute("auth_error_type");
            session.removeAttribute("token_error");
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            logger.info("User is authenticated: {}", oidcUser.getSubject());
            model.addAttribute("authenticated", true);
            model.addAttribute("userInfo", oidcUser.getUserInfo());
            model.addAttribute("idToken", oidcUser.getIdToken().getTokenValue());
            model.addAttribute("tokenClaims", session.getAttribute("token_claims"));
            model.addAttribute("accessToken", session.getAttribute("access_token"));
        } else {
            logger.info("No authenticated user");
            model.addAttribute("authenticated", false);
        }
        return "home";
    }
}
