package scot.gov.scotaccountclient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Controller
public class LogoutController {
    private static final Logger logger = LoggerFactory.getLogger(LogoutController.class);

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        logger.info("Initiating logout process for user: {}",
                authentication != null ? authentication.getName() : "anonymous");

        try {
            // Log session invalidation
            HttpSession session = request.getSession(false);
            if (session != null) {
                logger.debug("Invalidating session: {}", session.getId());
                session.invalidate();
            }

            // Log authentication clearing
            SecurityContextHolder.clearContext();
            logger.debug("Security context cleared");

            logger.info("Logout completed successfully");
            return "redirect:/";
        } catch (Exception e) {
            logger.error("Error during logout process", e);
            return "redirect:/?error=logout_failed";
        }
    }
}