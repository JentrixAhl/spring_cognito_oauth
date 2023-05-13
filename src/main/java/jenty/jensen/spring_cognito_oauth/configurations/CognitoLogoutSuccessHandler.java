package jenty.jensen.spring_cognito_oauth.configurations;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

public abstract class CognitoLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
    protected abstract String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication);
}
