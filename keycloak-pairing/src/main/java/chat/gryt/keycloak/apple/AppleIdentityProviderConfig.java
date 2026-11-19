package chat.gryt.keycloak.apple;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/** The .p8 key goes in clientSecret, so the admin console hides it and vault references work. */
public class AppleIdentityProviderConfig extends OIDCIdentityProviderConfig {

    public AppleIdentityProviderConfig() { }

    public AppleIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    String getTeamId() {
        return getConfig().get("teamId");
    }

    String getKeyId() {
        return getConfig().get("keyId");
    }
}
