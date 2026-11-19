package chat.gryt.keycloak.apple;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.time.Instant;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.vault.VaultStringSecret;

/**
 * Sign in with Apple. Keycloak's own OIDC broker can't do it: Apple posts the result back
 * (form_post) when email is asked for, and its client secret is a JWT we have to sign.
 */
public class AppleIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

    static final String ISSUER = "https://appleid.apple.com";

    public AppleIdentityProvider(KeycloakSession session, AppleIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(ISSUER + "/auth/authorize");
        config.setTokenUrl(ISSUER + "/auth/token");
        config.setIssuer(ISSUER);
        // Apple has no userinfo endpoint; the email is in the id token.
        config.setDisableUserInfoService(true);
    }

    @Override
    protected String getDefaultScopes() {
        return "openid email";
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        return super.createAuthorizationUrl(request).queryParam("response_mode", "form_post");
    }

    @Override
    public SimpleHttpRequest authenticateTokenRequest(SimpleHttpRequest tokenRequest) {
        AppleIdentityProviderConfig config = (AppleIdentityProviderConfig) getConfig();
        try (VaultStringSecret p8 = session.vault().getStringSecret(config.getClientSecret())) {
            String secret = AppleClientSecret.mint(p8.get().orElse(config.getClientSecret()),
                    config.getTeamId(), config.getKeyId(), config.getClientId(), Instant.now());
            return tokenRequest
                    .param(OAuth2Constants.CLIENT_ID, config.getClientId())
                    .param(OAuth2Constants.CLIENT_SECRET, secret);
        }
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new AppleEndpoint(callback, realm, event, this);
    }

    protected static class AppleEndpoint extends OIDCEndpoint {

        public AppleEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event, AppleIdentityProvider provider) {
            super(callback, realm, event, provider);
        }

        // Apple's `user` field (the name, sent once) is ignored: Gryt's profile is email only.
        @POST
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        public Response formPost(@FormParam(OAuth2Constants.STATE) String state,
                                 @FormParam(OAuth2Constants.CODE) String code,
                                 @FormParam(OAuth2Constants.ERROR) String error,
                                 @FormParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription) {
            return authResponse(state, code, error, errorDescription);
        }
    }
}
