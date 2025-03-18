package uk.aiapplied.scotaccountclient;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
public class LogoutController {
    private static final Logger logger = LoggerFactory.getLogger(LogoutController.class);

    @Value("${spring.security.oauth2.client.registration.scotaccount.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.scotaccount.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.scotaccount.scope}")
    private String scope;

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getPrincipal())) {
            OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
            OidcUser oidcUser = (OidcUser) oauth2Token.getPrincipal();
            String idToken = oidcUser.getIdToken().getTokenValue();

            String logoutUrl = UriComponentsBuilder
                .fromUriString("https://authz.scotaccount.service.gov.scot/authorize/logout")
                .queryParam("id_token_hint", idToken)
                .queryParam("post_logout_redirect_uri", "http://localhost:8080/")
                .queryParam("state", "logout-" + System.currentTimeMillis())
                .build()
                .toUriString();

            logger.info("Redirecting to ScotAccount logout URL: {}", logoutUrl);
            return "redirect:" + logoutUrl;
        }

        return "redirect:/";
    }
} 