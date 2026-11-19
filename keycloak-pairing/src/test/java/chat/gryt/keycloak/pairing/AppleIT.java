package chat.gryt.keycloak.pairing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import chat.gryt.keycloak.pairing.TestKeycloak.Resp;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Sign in with Apple, up to the point where Apple itself would take over. */
class AppleIT {

    private static TestKeycloak kc;
    private static Oidc oidc;

    @BeforeAll
    static void start() throws Exception {
        kc = new TestKeycloak();
        kc.createRealm();
        oidc = new Oidc(kc);
        kc.admin("POST", "/" + TestKeycloak.REALM + "/identity-provider/instances", Map.of(
                "alias", "apple", "providerId", "apple", "enabled", true, "trustEmail", false,
                "config", Map.of("clientId", "chat.gryt.signin", "clientSecret", "unused-here",
                        "teamId", "TEAM123456", "keyId", "KEY1234567")));
    }

    @AfterAll
    static void stop() {
        if (kc != null) kc.close();
    }

    private static String param(String url, String name) {
        for (String part : URI.create(url).getRawQuery().split("&")) {
            String[] kv = part.split("=", 2);
            if (kv[0].equals(name)) return URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
        }
        return null;
    }

    @Test
    void sendsYouToAppleAskingForAPostBackAndTakesThePost() {
        Map<String, String> jar = new HashMap<>();
        String path = "/realms/" + TestKeycloak.REALM;
        String query = TestKeycloak.form(Map.of(
                "client_id", PairingResource.CLIENT_ID, "redirect_uri", Oidc.REDIRECT, "response_type", "code",
                "scope", "openid", "state", "s", "kc_idp_hint", "apple"));
        Resp hint = oidc.withCookies(jar, "GET", path + "/protocol/openid-connect/auth?" + query, null);
        String toBroker = hint.header("Location");
        assertTrue(toBroker != null && toBroker.contains("/broker/apple/login"), hint.status() + " " + toBroker);

        Resp broker = oidc.withCookies(jar, "GET", toBroker, null);
        String toApple = broker.header("Location");
        assertTrue(toApple != null && toApple.startsWith("https://appleid.apple.com/auth/authorize"), broker.status() + " " + toApple);
        assertEquals("form_post", param(toApple, "response_mode"));
        assertEquals("chat.gryt.signin", param(toApple, "client_id"));

        // The person cancels on Apple's page; Apple posts that back. Keycloak's own broker answers 405 here.
        Resp back = oidc.withCookies(jar, "POST", path + "/broker/apple/endpoint",
                Map.of("state", param(toApple, "state"), "error", "user_cancelled_authorize"));
        assertTrue(back.status() != 405 && back.status() < 500, back.status() + " " + back.body());
    }
}
