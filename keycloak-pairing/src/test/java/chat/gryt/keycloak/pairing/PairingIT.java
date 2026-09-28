package chat.gryt.keycloak.pairing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import chat.gryt.keycloak.pairing.Oidc.Device;
import chat.gryt.keycloak.pairing.Oidc.Session;
import chat.gryt.keycloak.pairing.TestKeycloak.Resp;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

/** The whole device flow against the Keycloak image the compose file runs, with the built jar. */
class PairingIT {

    private static final String PASSWORD = "correct horse battery staple";
    // The realm's polling interval is 5 s; polling sooner gets slow_down.
    private static final long POLL_WAIT_MS = 5_500;

    private static TestKeycloak kc;
    private static Oidc oidc;

    @BeforeAll
    static void start() throws Exception {
        kc = new TestKeycloak();
        kc.createRealm();
        oidc = new Oidc(kc);
    }

    @AfterAll
    static void stop() {
        if (kc != null) kc.close();
    }

    private record User(String id, String name, Session session) { }

    // One user per test, since the rate limits are per user.
    private static User user(TestInfo info) {
        String name = info.getTestMethod().orElseThrow().getName().toLowerCase();
        String id = kc.createUser(name, PASSWORD);
        return new User(id, name, oidc.login(PairingResource.CLIENT_ID, name, PASSWORD));
    }

    private static void assertRefused(Resp r, int status, String error) {
        assertEquals(status, r.status(), r.body());
        assertEquals(error, r.json().path("error").asText(), r.body());
    }

    private static void assertDenied(Device d) throws InterruptedException {
        Resp poll = oidc.poll(d);
        assertEquals(400, poll.status(), poll.body());
        assertEquals("access_denied", poll.json().path("error").asText(), poll.body());
    }

    @Test
    void theProviderLoads() {
        assertTrue(kc.container.getLogs().contains(PairingResourceProviderFactory.ID), "no mention of the provider at startup");
    }

    @Test
    void approvesAndTheNewDeviceGetsItsOwnSession(TestInfo info) throws Exception {
        User a = user(info);
        JsonNode aId = Oidc.claims(a.session().first.get("id_token").asText());
        // So an auth_time copied from A can't be confused with one stamped at approval.
        Thread.sleep(2_000);

        Device n = oidc.startDevice();
        assertEquals("authorization_pending", oidc.poll(n).json().path("error").asText());

        String at = oidc.freshAccessToken(a.session());
        // Typed the way a person might: lower case, no dash.
        Resp ok = oidc.approve(at, n.userCode().toLowerCase().replace("-", ""), n.nonce());
        assertEquals(204, ok.status(), ok.body());

        Thread.sleep(POLL_WAIT_MS);
        Resp tokens = oidc.poll(n);
        assertEquals(200, tokens.status(), tokens.body());
        JsonNode id = Oidc.claims(tokens.json().get("id_token").asText());
        JsonNode access = Oidc.claims(tokens.json().get("access_token").asText());
        JsonNode refresh = Oidc.claims(tokens.json().get("refresh_token").asText());

        assertEquals(n.nonce(), id.path("nonce").asText());
        assertEquals(a.id(), id.path("sub").asText());
        assertEquals(PairingResource.CLIENT_ID, id.path("azp").asText());
        assertEquals("Offline", refresh.path("typ").asText());
        assertTrue(Set.of(access.path("scope").asText().split(" ")).containsAll(List.of("openid", "profile", "email", "offline_access")));
        assertNotEquals(Oidc.claims(at).path("sid").asText(), access.path("sid").asText(), "N shares A's session");

        long authTime = id.path("auth_time").asLong();
        assertEquals(aId.path("auth_time").asLong(), authTime, "auth_time is not A's");
        assertTrue(authTime < id.path("iat").asLong() - 1);

        // N's session stands on its own: it refreshes.
        Resp nRefresh = kc.postForm("/realms/gryt/protocol/openid-connect/token", Map.of(
                "grant_type", "refresh_token", "client_id", PairingResource.CLIENT_ID,
                "refresh_token", tokens.json().get("refresh_token").asText()), Map.of());
        assertEquals(200, nRefresh.status(), nRefresh.body());

        JsonNode events = kc.events("OAUTH2_DEVICE_VERIFY_USER_CODE", a.id());
        assertEquals(1, events.size(), events.toString());
        JsonNode details = events.get(0).get("details");
        assertEquals("true", details.path("gryt_pairing").asText());
        assertEquals(Oidc.claims(at).path("sid").asText(), details.path("approving_session").asText());
        assertEquals(access.path("sid").asText(), details.path("new_session").asText());
        String canonical = n.userCode().replace("-", "");
        details.properties().forEach(e -> assertFalse(
                e.getValue().asText().replace("-", "").equalsIgnoreCase(canonical), "the user code is in the event"));
    }

    @Test
    void theVerifierIsStillRequired(TestInfo info) throws Exception {
        User a = user(info);
        Device n = oidc.startDevice();
        assertEquals(204, oidc.approve(oidc.freshAccessToken(a.session()), n.userCode(), n.nonce()).status());

        Resp none = oidc.pollWith(n, null);
        assertEquals(400, none.status(), none.body());
        Thread.sleep(POLL_WAIT_MS);
        Resp wrong = oidc.pollWith(n, Oidc.random(48));
        assertEquals(400, wrong.status(), wrong.body());
        assertEquals("invalid_grant", wrong.json().path("error").asText(), wrong.body());
    }

    @Test
    void aWrongBindingDeniesTheCode(TestInfo info) throws Exception {
        User a = user(info);
        Device n = oidc.startDevice();
        assertRefused(oidc.approve(oidc.freshAccessToken(a.session()), n.userCode(), "kc-somebody-else"), 403, "binding_mismatch");
        assertDenied(n);
        // Nobody gets a second try at the same code, even with the right binding.
        assertRefused(oidc.approve(oidc.freshAccessToken(a.session()), n.userCode(), n.nonce()), 409, "code_used");

        JsonNode errors = kc.events("OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR", a.id());
        List<String> reasons = errors.findValuesAsText("error");
        assertTrue(reasons.containsAll(List.of("binding_mismatch", "code_used")), reasons.toString());

        // The label monitoring/alert.rules.yml sums over.
        assertTrue(kc.metrics().lines().anyMatch(l -> l.startsWith("keycloak_user_events_total{")
                && l.contains("event=\"oauth2_device_verify_user_code\"") && l.contains("error=\"binding_mismatch\"")),
                "no oauth2_device_verify_user_code error in /metrics");
    }

    @Test
    void aSecondCallIsRefused(TestInfo info) {
        User a = user(info);
        Device n = oidc.startDevice();
        assertEquals(204, oidc.approve(oidc.freshAccessToken(a.session()), n.userCode(), n.nonce()).status());
        assertRefused(oidc.approve(oidc.freshAccessToken(a.session()), n.userCode(), n.nonce()), 400, "unknown_code");
    }

    @Test
    void noTokenIsRefused() throws Exception {
        Device n = oidc.startDevice();
        assertRefused(oidc.approve(null, n.userCode(), n.nonce()), 401, "invalid_token");
        assertDenied(n);
    }

    @Test
    void anotherClientsTokenIsRefused(TestInfo info) throws Exception {
        User a = user(info);
        Session other = oidc.login("other-app", a.name(), PASSWORD);
        Device n = oidc.startDevice();
        assertRefused(oidc.approve(oidc.freshAccessToken(other), n.userCode(), n.nonce()), 403, "wrong_client");
        assertDenied(n);
    }

    @Test
    void aTokenOlderThanSixtySecondsIsRefused(TestInfo info) throws Exception {
        User a = user(info);
        String at = oidc.freshAccessToken(a.session());
        Thread.sleep((PairingResource.MAX_TOKEN_AGE_SECONDS + 2) * 1000L);
        Device n = oidc.startDevice();
        assertRefused(oidc.approve(at, n.userCode(), n.nonce()), 403, "stale_token");
        assertDenied(n);
    }

    @Test
    void pendingRequiredActionsAreRefused(TestInfo info) throws Exception {
        User a = user(info);
        kc.updateUser(a.id(), Map.of("requiredActions", List.of("VERIFY_EMAIL")));
        Device n = oidc.startDevice();
        assertRefused(oidc.approve(oidc.freshAccessToken(a.session()), n.userCode(), n.nonce()), 403, "required_actions");
        assertDenied(n);
    }

    @Test
    void aLockedOutUserIsRefused(TestInfo info) throws Exception {
        User a = user(info);
        String at = oidc.freshAccessToken(a.session());
        for (int i = 0; i < 3; i++) oidc.failLogin(a.name());
        Device n = oidc.startDevice();
        assertRefused(oidc.approve(at, n.userCode(), n.nonce()), 403, "user_locked");
        assertDenied(n);
    }

    @Test
    void aDisabledUserIsRefused(TestInfo info) throws Exception {
        User a = user(info);
        String at = oidc.freshAccessToken(a.session());
        kc.updateUser(a.id(), Map.of("enabled", false));
        Device n = oidc.startDevice();
        Resp r = oidc.approve(at, n.userCode(), n.nonce());
        // Keycloak's own token check already refuses a disabled user's token.
        assertTrue(r.status() == 401 || r.status() == 403, r.body());
        assertDenied(n);
    }

    @Test
    void anExpiredCodeIsRefused(TestInfo info) throws Exception {
        User a = user(info);
        kc.setDeviceGrant("2");
        Device n;
        try {
            n = oidc.startDevice();
        } finally {
            kc.setDeviceGrant("300");
        }
        Thread.sleep(3_500);
        Resp r = oidc.approve(oidc.freshAccessToken(a.session()), n.userCode(), n.nonce());
        assertTrue(Set.of("unknown_code", "expired_code").contains(r.json().path("error").asText()), r.body());
    }

    @Test
    void aMalformedBodyIsRefused(TestInfo info) {
        User a = user(info);
        String at = oidc.freshAccessToken(a.session());
        Resp r = kc.send("POST", "/realms/gryt/gryt-pairing/approve", "application/json", "{\"user_code\": 5}",
                Map.of("Authorization", "Bearer " + at));
        assertRefused(r, 400, "bad_request");
    }

    @Test
    void approvalsAreRateLimited(TestInfo info) throws Exception {
        User a = user(info);
        for (int i = 0; i < PairingLimits.APPROVALS_PER_HOUR; i++) {
            Device n = oidc.startDevice();
            assertEquals(204, oidc.approve(oidc.freshAccessToken(a.session()), n.userCode(), n.nonce()).status());
        }
        Device n = oidc.startDevice();
        assertRefused(oidc.approve(oidc.freshAccessToken(a.session()), n.userCode(), n.nonce()), 429, "rate_limited");
        assertDenied(n);
    }

    @Test
    void failuresBlockTheUserForAnHour(TestInfo info) throws Exception {
        User a = user(info);
        for (int i = 0; i < PairingLimits.FAILURES_PER_HOUR; i++) {
            Device n = oidc.startDevice();
            assertRefused(oidc.approve(oidc.freshAccessToken(a.session()), n.userCode(), "wrong"), 403, "binding_mismatch");
        }
        Device n = oidc.startDevice();
        assertRefused(oidc.approve(oidc.freshAccessToken(a.session()), n.userCode(), n.nonce()), 429, "rate_limited");
        assertDenied(n);
    }

    @Test
    void corsFollowsTheClientsWebOrigins(TestInfo info) {
        Resp preflight = kc.send("OPTIONS", "/realms/gryt/gryt-pairing/approve", null, null, Map.of(
                "Origin", "http://localhost:3666", "Access-Control-Request-Method", "POST",
                "Access-Control-Request-Headers", "authorization,content-type"));
        assertEquals(200, preflight.status(), preflight.body());
        assertEquals("http://localhost:3666", preflight.header("Access-Control-Allow-Origin"));

        User a = user(info);
        String at = oidc.freshAccessToken(a.session());
        Device n = oidc.startDevice();
        Resp allowed = kc.send("POST", "/realms/gryt/gryt-pairing/approve", "application/json",
                TestKeycloak.JSON.createObjectNode().put("user_code", n.userCode()).put("binding", n.nonce()).toString(),
                Map.of("Authorization", "Bearer " + at, "Origin", "http://localhost:3666"));
        assertEquals(204, allowed.status(), allowed.body());
        assertEquals("http://localhost:3666", allowed.header("Access-Control-Allow-Origin"));

        Device other = oidc.startDevice();
        Resp foreign = kc.send("POST", "/realms/gryt/gryt-pairing/approve", "application/json",
                TestKeycloak.JSON.createObjectNode().put("user_code", other.userCode()).put("binding", "x").toString(),
                Map.of("Authorization", "Bearer " + oidc.freshAccessToken(a.session()), "Origin", "https://evil.example"));
        assertNull(foreign.header("Access-Control-Allow-Origin"));
        assertNotNull(foreign.json().path("error").asText(null));
    }
}
