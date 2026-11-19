package chat.gryt.keycloak.apple;

import java.util.List;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class AppleIdentityProviderFactory extends AbstractIdentityProviderFactory<AppleIdentityProvider>
        implements SocialIdentityProviderFactory<AppleIdentityProvider> {

    public static final String ID = "apple";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getName() {
        return "Apple";
    }

    @Override
    public AppleIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new AppleIdentityProvider(session, new AppleIdentityProviderConfig(model));
    }

    @Override
    public AppleIdentityProviderConfig createConfig() {
        return new AppleIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name("teamId").label("Team ID")
                .helpText("Your Apple Developer team id. The client ID is the Services ID; the client secret is the .p8 key.")
                .type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name("keyId").label("Key ID")
                .helpText("The id of the Sign in with Apple key.")
                .type(ProviderConfigProperty.STRING_TYPE).add()
                .build();
    }
}
