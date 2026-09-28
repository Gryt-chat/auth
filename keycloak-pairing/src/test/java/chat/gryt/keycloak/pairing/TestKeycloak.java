package chat.gryt.keycloak.pairing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.File;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/** A throwaway Keycloak in a container, with the built jar in providers/ and a realm made for the test. */
final class TestKeycloak implements AutoCloseable {

    static final ObjectMapper JSON = new ObjectMapper();
    static final String REALM = "gryt";
    static final String ADMIN_PASSWORD = "throwaway-admin";

    record Resp(int status, String body, Map<String, List<String>> headers) {
        JsonNode json() {
            try {
                return body == null || body.isEmpty() ? JSON.nullNode() : JSON.readTree(body);
            } catch (Exception e) {
                throw new AssertionError("not JSON (" + status + "): " + body, e);
            }
        }

        String header(String name) {
            return headers.entrySet().stream()
                    .filter(e -> e.getKey().equalsIgnoreCase(name))
                    .flatMap(e -> e.getValue().stream())
                    .findFirst().orElse(null);
        }
    }

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    final GenericContainer<?> container;
    final String base;

    TestKeycloak() {
        String version = System.getProperty("keycloak.version");
        String jar = System.getProperty("pairing.jar");
        if (version == null || jar == null || !new File(jar).isFile()) {
            throw new IllegalStateException("run through `mvn verify`, which builds the jar and sets keycloak.version");
        }
        container = new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:" + version))
                .withCopyFileToContainer(MountableFile.forHostPath(jar), "/opt/keycloak/providers/gryt-pairing.jar")
                .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
                .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
                .withEnv("KC_DB", "dev-file")
                .withEnv("KC_HTTP_ENABLED", "true")
                .withEnv("KC_HOSTNAME_STRICT", "false")
                .withEnv("KC_HEALTH_ENABLED", "true")
                .withEnv("KC_METRICS_ENABLED", "true")
                .withEnv("KC_FEATURES", "user-event-metrics,update-email,recovery-codes")
                .withEnv("KC_EVENT_METRICS_USER_ENABLED", "true")
                .withCommand("start")
                .withExposedPorts(8080, 9000)
                .waitingFor(Wait.forHttp("/health/ready").forPort(9000).withStartupTimeout(Duration.ofMinutes(5)));
        container.start();
        base = "http://" + container.getHost() + ":" + container.getMappedPort(8080);
    }

    @Override
    public void close() {
        container.stop();
    }

    // ── plain HTTP ───────────────────────────────────────────────

    Resp send(String method, String path, String contentType, String body, Map<String, String> headers) {
        String url = path.startsWith("http") ? path : base + path;
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30));
        if (contentType != null) b.header("Content-Type", contentType);
        headers.forEach(b::header);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        try {
            HttpResponse<String> r = HTTP.send(b.build(), HttpResponse.BodyHandlers.ofString());
            return new Resp(r.statusCode(), r.body(), r.headers().map());
        } catch (Exception e) {
            throw new AssertionError(method + " " + url, e);
        }
    }

    Resp postForm(String path, Map<String, String> form, Map<String, String> headers) {
        return send("POST", path, "application/x-www-form-urlencoded", form(form), headers);
    }

    static String form(Map<String, String> fields) {
        return fields.entrySet().stream()
                .map(e -> enc(e.getKey()) + "=" + enc(e.getValue()))
                .collect(Collectors.joining("&"));
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    // ── admin API ────────────────────────────────────────────────

    String adminToken() {
        Resp r = postForm("/realms/master/protocol/openid-connect/token", Map.of(
                "grant_type", "password", "client_id", "admin-cli",
                "username", "admin", "password", ADMIN_PASSWORD), Map.of());
        if (r.status() != 200) throw new AssertionError("admin token: " + r.body());
        return r.json().get("access_token").asText();
    }

    Resp admin(String method, String path, Object body) {
        try {
            String json = body == null ? null : JSON.writeValueAsString(body);
            Resp r = send(method, "/admin/realms" + path, json == null ? null : "application/json", json,
                    Map.of("Authorization", "Bearer " + adminToken()));
            if (r.status() >= 300) throw new AssertionError(method + " " + path + " -> " + r.status() + " " + r.body());
            return r;
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new AssertionError(e);
        }
    }

    /** The realm, gryt-web copied from realm/gryt-realm.json, and the device grant turned on. */
    void createRealm() throws Exception {
        admin("POST", "", Map.of(
                "realm", REALM,
                "enabled", true,
                "bruteForceProtected", true,
                "failureFactor", 3,
                "eventsEnabled", true,
                "enabledEventTypes", List.of("OAUTH2_DEVICE_VERIFY_USER_CODE", "OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR")));

        JsonNode realmFile = JSON.readTree(new File(System.getProperty("realm.file")));
        ObjectNode web = null;
        for (JsonNode c : realmFile.get("clients")) {
            if (PairingResource.CLIENT_ID.equals(c.path("clientId").asText())) web = ((ObjectNode) c).deepCopy();
        }
        if (web == null) throw new AssertionError("gryt-web is not in the realm file");
        web.remove("id");
        admin("POST", "/" + REALM + "/clients", web);
        setDeviceGrant("300");

        admin("POST", "/" + REALM + "/clients", Map.of(
                "clientId", "other-app",
                "publicClient", true,
                "standardFlowEnabled", true,
                "redirectUris", List.of("http://localhost:3666/*"),
                "attributes", Map.of("pkce.code.challenge.method", "S256")));
    }

    /** The same GET and PUT as bootstrap/enable_device_grant.py. */
    void setDeviceGrant(String lifespanSeconds) {
        String id = clientUuid(PairingResource.CLIENT_ID);
        ObjectNode client = (ObjectNode) admin("GET", "/" + REALM + "/clients/" + id, null).json();
        ObjectNode attributes = (ObjectNode) client.get("attributes");
        attributes.put("oauth2.device.authorization.grant.enabled", "true");
        attributes.put("oauth2.device.code.lifespan", lifespanSeconds);
        attributes.put("oauth2.device.polling.interval", "5");
        admin("PUT", "/" + REALM + "/clients/" + id, client);
    }

    String clientUuid(String clientId) {
        return admin("GET", "/" + REALM + "/clients?clientId=" + enc(clientId), null).json().get(0).get("id").asText();
    }

    String createUser(String username, String password) {
        admin("POST", "/" + REALM + "/users", Map.of(
                "username", username,
                "enabled", true,
                "email", username + "@example.test",
                "emailVerified", true,
                "firstName", "Test",
                "lastName", username,
                "credentials", List.of(Map.of("type", "password", "value", password, "temporary", false))));
        return admin("GET", "/" + REALM + "/users?exact=true&username=" + enc(username), null).json().get(0).get("id").asText();
    }

    void updateUser(String userId, Map<String, Object> fields) {
        ObjectNode user = (ObjectNode) admin("GET", "/" + REALM + "/users/" + userId, null).json();
        user.setAll((ObjectNode) JSON.valueToTree(fields));
        admin("PUT", "/" + REALM + "/users/" + userId, user);
    }

    String metrics() {
        return send("GET", "http://" + container.getHost() + ":" + container.getMappedPort(9000) + "/metrics",
                null, null, Map.of()).body();
    }

    JsonNode events(String type, String userId) {
        return admin("GET", "/" + REALM + "/events?type=" + type + "&user=" + userId, null).json();
    }
}
