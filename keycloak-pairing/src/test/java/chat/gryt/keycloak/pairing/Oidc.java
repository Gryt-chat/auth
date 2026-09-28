package chat.gryt.keycloak.pairing;

import chat.gryt.keycloak.pairing.TestKeycloak.Resp;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The OIDC calls the apps make: a code-flow sign-in, a refresh, and both ends of the device grant. */
final class Oidc {

    static final String REDIRECT = "http://localhost:3666/cb";
    static final String APP_SCOPE = "openid profile email offline_access";
    static final String DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern FORM_ACTION = Pattern.compile("<form[^>]*action=\"([^\"]+)\"");

    private final TestKeycloak kc;
    private final String realmPath;

    Oidc(TestKeycloak kc) {
        this.kc = kc;
        this.realmPath = "/realms/" + TestKeycloak.REALM;
    }

    /** A signed-in app: the token response plus the refresh token it keeps rotating. */
    static final class Session {
        final String clientId;
        final JsonNode first;
        String refreshToken;

        Session(String clientId, JsonNode first) {
            this.clientId = clientId;
            this.first = first;
            this.refreshToken = first.get("refresh_token").asText();
        }
    }

    record Device(String deviceCode, String userCode, String verifier, String nonce) { }

    // ── sign-in ─────────────────────────────────────────────────

    Session login(String clientId, String username, String password) {
        Map<String, String> cookies = new HashMap<>();
        String[] pkce = pkce();
        String query = TestKeycloak.form(Map.of(
                "client_id", clientId, "redirect_uri", REDIRECT, "response_type", "code",
                "scope", APP_SCOPE, "state", "s", "nonce", "n",
                "code_challenge", pkce[1], "code_challenge_method", "S256"));
        Resp page = withCookies(cookies, "GET", realmPath + "/protocol/openid-connect/auth?" + query, null);
        Resp done = withCookies(cookies, "POST", formAction(page),
                Map.of("username", username, "password", password, "credentialId", ""));
        String location = done.header("Location");
        if (done.status() != 302 || location == null || !location.startsWith(REDIRECT)) {
            throw new AssertionError("sign-in for " + username + " did not redirect back: " + done.status());
        }
        String code = queryParam(location, "code");
        Resp tokens = kc.postForm(realmPath + "/protocol/openid-connect/token", Map.of(
                "grant_type", "authorization_code", "client_id", clientId, "code", code,
                "redirect_uri", REDIRECT, "code_verifier", pkce[0]), Map.of());
        if (tokens.status() != 200) throw new AssertionError("code exchange: " + tokens.body());
        return new Session(clientId, tokens.json());
    }

    /** Posts a wrong password, the way brute-force protection counts a failure. */
    void failLogin(String username) {
        Map<String, String> cookies = new HashMap<>();
        String[] pkce = pkce();
        String query = TestKeycloak.form(Map.of(
                "client_id", PairingResource.CLIENT_ID, "redirect_uri", REDIRECT, "response_type", "code",
                "scope", "openid", "code_challenge", pkce[1], "code_challenge_method", "S256"));
        Resp page = withCookies(cookies, "GET", realmPath + "/protocol/openid-connect/auth?" + query, null);
        Resp r = withCookies(cookies, "POST", formAction(page),
                Map.of("username", username, "password", "wrong-" + username, "credentialId", ""));
        if (r.status() == 302) throw new AssertionError("a wrong password signed in");
    }

    /** A freshly issued access token, the way A refreshes right before calling the extension. */
    String freshAccessToken(Session s) {
        Resp r = kc.postForm(realmPath + "/protocol/openid-connect/token", Map.of(
                "grant_type", "refresh_token", "client_id", s.clientId, "refresh_token", s.refreshToken), Map.of());
        if (r.status() != 200) throw new AssertionError("refresh: " + r.body());
        s.refreshToken = r.json().get("refresh_token").asText();
        return r.json().get("access_token").asText();
    }

    // ── device grant ─────────────────────────────────────────────

    Device startDevice() {
        return startDevice("kc-" + random(32));
    }

    Device startDevice(String nonce) {
        String[] pkce = pkce();
        Resp r = kc.postForm(realmPath + "/protocol/openid-connect/auth/device", Map.of(
                "client_id", PairingResource.CLIENT_ID, "scope", APP_SCOPE, "nonce", nonce,
                "code_challenge", pkce[1], "code_challenge_method", "S256"), Map.of());
        if (r.status() != 200) throw new AssertionError("device authorization: " + r.body());
        return new Device(r.json().get("device_code").asText(), r.json().get("user_code").asText(), pkce[0], nonce);
    }

    Resp poll(Device d) {
        return pollWith(d, d.verifier());
    }

    Resp pollWith(Device d, String verifier) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", DEVICE_GRANT);
        form.put("client_id", PairingResource.CLIENT_ID);
        form.put("device_code", d.deviceCode());
        if (verifier != null) form.put("code_verifier", verifier);
        return kc.postForm(realmPath + "/protocol/openid-connect/token", form, Map.of());
    }

    Resp approve(String accessToken, String userCode, String binding) {
        String body = TestKeycloak.JSON.createObjectNode().put("user_code", userCode).put("binding", binding).toString();
        Map<String, String> headers = accessToken == null ? Map.of() : Map.of("Authorization", "Bearer " + accessToken);
        return kc.send("POST", realmPath + "/gryt-pairing/approve", "application/json", body, headers);
    }

    // ── helpers ─────────────────────────────────────────────────

    static JsonNode claims(String jwt) {
        try {
            return TestKeycloak.JSON.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    static String random(int bytes) {
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String[] pkce() {
        try {
            String verifier = random(48);
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return new String[] {verifier, Base64.getUrlEncoder().withoutPadding().encodeToString(hash)};
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    // Keycloak marks its cookies Secure, which java.net's cookie store won't send over plain http.
    private Resp withCookies(Map<String, String> jar, String method, String url, Map<String, String> form) {
        Map<String, String> headers = new HashMap<>();
        if (!jar.isEmpty()) {
            headers.put("Cookie", String.join("; ", jar.entrySet().stream().map(e -> e.getKey() + "=" + e.getValue()).toList()));
        }
        Resp r = form == null
                ? kc.send(method, url, null, null, headers)
                : kc.send(method, url, "application/x-www-form-urlencoded", TestKeycloak.form(form), headers);
        for (Map.Entry<String, List<String>> h : r.headers().entrySet()) {
            if (!h.getKey().equalsIgnoreCase("set-cookie")) continue;
            for (String c : h.getValue()) {
                String pair = c.split(";", 2)[0];
                int eq = pair.indexOf('=');
                if (eq > 0) jar.put(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim());
            }
        }
        return r;
    }

    private static String formAction(Resp page) {
        Matcher m = FORM_ACTION.matcher(page.body());
        if (page.status() != 200 || !m.find()) throw new AssertionError("no login form (" + page.status() + ")");
        return m.group(1).replace("&amp;", "&");
    }

    private static String queryParam(String url, String name) {
        for (String part : URI.create(url).getRawQuery().split("&")) {
            String[] kv = part.split("=", 2);
            if (kv[0].equals(name)) return java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
        }
        throw new AssertionError(name + " missing from " + url);
    }
}
