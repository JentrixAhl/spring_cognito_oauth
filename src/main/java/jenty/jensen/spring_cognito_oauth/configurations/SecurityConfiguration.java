package jenty.jensen.spring_cognito_oauth.configurations;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.net.URI;

@Configuration
public class SecurityConfiguration {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    public static CognitoIdentityProviderClient getCognitoClient() {
        var credentialsProvider = ProfileCredentialsProvider.create();

        var cognitoClient = CognitoIdentityProviderClient.builder()
                .region(Region.EU_NORTH_1)
                .credentialsProvider(credentialsProvider)
                .build();

        return cognitoClient;
    }
    public static void deleteUser(String username) {

        try{
            DeleteUserRequest deleteUserRequest = DeleteUserRequest.builder()
                    .accessToken(username)
                    .build();

            AdminDeleteUserRequest userRequest = AdminDeleteUserRequest.builder()
                    .username(username)
                    .userPoolId("eu-north-1_vYjUKA2Hg")
                    .build() ;

            CognitoIdentityProviderClient cognitoClient = getCognitoClient();
            AdminDeleteUserResponse response = cognitoClient.adminDeleteUser(userRequest);

            System.out.println("User account deleted successful");

        } catch (CognitoIdentityProviderException e) {
            System.err.println(e.awsErrorDetails().errorMessage());
            System.exit(1);
        }
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers("/", "/login-success", "/delete-success").permitAll()
                .anyRequest().authenticated();

        http.oauth2Login()
                .defaultSuccessUrl("/");


        var logoutSuccessHandler = new CognitoLogoutSuccessHandler(clientRegistrationRepository);

        http.logout().logoutSuccessHandler(logoutSuccessHandler);


        return http.build();

    }

    class CognitoLogoutSuccessHandler extends jenty.jensen.spring_cognito_oauth.configurations.CognitoLogoutSuccessHandler {
        private ClientRegistrationRepository clientRegistrationRepository;

        public CognitoLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
            this.clientRegistrationRepository = clientRegistrationRepository;
        }

        @Override
        protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication){
            var oauth2Token = (OAuth2AuthenticationToken) authentication;

            var clientRegistration = getClientRegistration(oauth2Token);

            var logoutUrl = getLogoutUrl(clientRegistration);
            var clientId = clientRegistration.getClientId();

            var basePath = ServletUriComponentsBuilder.fromRequestUri(request)
                    .replacePath(null)
                    .build()
                    .toUriString();


            var targetUrl = UriComponentsBuilder
                    .fromUri(URI.create(logoutUrl))
                    .queryParam("client_id", clientId)
                    .queryParam("logout_uri", basePath + "/")
                    .queryParam("redirect_uri", basePath + "/")
                    .queryParam("response_type", "code")
                    .toUriString();

            return targetUrl;
        }

        private String getLogoutUrl(ClientRegistration clientRegistration) {
            var providerDetails = clientRegistration.getProviderDetails();
            var authUri = providerDetails.getAuthorizationUri();
            return authUri.replace("oauth2/authorize", "logout");
        }

        private ClientRegistration getClientRegistration(OAuth2AuthenticationToken token){
            var registrationId = token.getAuthorizedClientRegistrationId();
            return clientRegistrationRepository.findByRegistrationId(registrationId);
        }

    }

}