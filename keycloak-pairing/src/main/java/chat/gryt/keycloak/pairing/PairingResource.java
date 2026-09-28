package chat.gryt.keycloak.pairing;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OAuth2DeviceCodeModel;
import org.keycloak.models.OAuth2DeviceUserCodeProvider;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.grants.device.DeviceGrantType;
import org.keycloak.protocol.oidc.grants.device.endpoints.DeviceEndpoint;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

/**
 * POST /realms/{realm}/gryt-pairing/approve: approves a device-grant user_code from inside the
 * app. The design is section 3 of docs/pairing-design.md in Gryt-chat/crypto.
 */
public class PairingResource implements RealmResourceProvider {

    static final String CLIENT_ID = "gryt-web";
    static final int MAX_TOKEN_AGE_SECONDS = 60;
    static final String APPROVED_BY_NOTE = "gryt.pairing.approvedBy";

    private static final int MAX_USER_CODE_LENGTH = 64;
    private static final int MAX_BINDING_LENGTH = 256;

    private final KeycloakSession session;

    PairingResource(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    @OPTIONS
    @Path("approve")
    public Response preflight() {
        return Cors.builder().auth().preflight().allowedMethods("POST", "OPTIONS").add(Response.ok());
    }

    @POST
    @Path("approve")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response approve(String body) {
        return new Call(session).run(body);
    }

    /** One request's state, so a refusal can deny the code and count the failure in one place. */
    private static final class Call {
        private final KeycloakSession session;
        private final RealmModel realm;
        private final ClientConnection connection;
        private final EventBuilder event;
        private final Cors cors;
        private final PairingLimits limits;
        private final int now = Time.currentTime();

        private String userCode;
        private boolean ownsCode;
        private UserModel user;

        Call(KeycloakSession session) {
            this.session = session;
            this.realm = session.getContext().getRealm();
            this.connection = session.getContext().getConnection();
            this.event = new EventBuilder(realm, session, connection)
                    .event(EventType.OAUTH2_DEVICE_VERIFY_USER_CODE)
                    .detail("gryt_pairing", "true");
            this.limits = new PairingLimits(session.singleUseObjects(), realm.getId());

            ClientModel web = realm.getClientByClientId(CLIENT_ID);
            Cors c = Cors.builder().auth().allowedMethods("POST");
            this.cors = web != null ? c.allowedOrigins(session, web) : c.allowedOrigins(new String[0]);
            if (web != null) event.client(web);
        }

        Response run(String body) {
            String rawCode;
            String binding;
            try {
                JsonNode json = JsonSerialization.mapper.readTree(body == null ? "" : body);
                rawCode = text(json, "user_code", MAX_USER_CODE_LENGTH);
                binding = text(json, "binding", MAX_BINDING_LENGTH);
            } catch (Exception e) {
                rawCode = null;
                binding = null;
            }
            if (rawCode == null || binding == null) {
                return refuse(400, "bad_request", false);
            }

            userCode = session.getProvider(OAuth2DeviceUserCodeProvider.class).format(rawCode);
            // Read before the token check so a bad token still uses up, and denies, the code.
            OAuth2DeviceCodeModel code = DeviceEndpoint.getDeviceByUserCode(session, realm, userCode);
            boolean usedBefore = false;
            if (code != null) {
                ownsCode = limits.claimCode(userCode, now, code.getExpiration());
                usedBefore = !ownsCode;
            }

            AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
            if (auth == null || auth.user() == null || auth.session() == null) {
                return refuse(401, "invalid_token", false);
            }
            user = auth.user();
            UserSessionModel approving = auth.session();
            AccessToken token = auth.token();
            event.user(user).detail("approving_session", approving.getId());

            if (usedBefore) {
                return refuse(409, "code_used", true);
            }
            if (limits.isBlocked(user.getId())) {
                return refuse(429, "rate_limited", false);
            }
            if (!CLIENT_ID.equals(token.getIssuedFor())) {
                return refuse(403, "wrong_client", true);
            }
            Long iat = token.getIat();
            if (iat == null || now - iat > MAX_TOKEN_AGE_SECONDS) {
                return refuse(403, "stale_token", true);
            }
            if (!user.isEnabled()) {
                return refuse(403, "user_disabled", true);
            }
            BruteForceProtector brute = session.getProvider(BruteForceProtector.class);
            if (brute.isTemporarilyDisabled(session, realm, user) || brute.isPermanentlyLockedOut(session, realm, user)) {
                return refuse(403, "user_locked", true);
            }
            if (user.getRequiredActionsStream().findAny().isPresent()) {
                return refuse(403, "required_actions", true);
            }
            if (limits.approvalsExhausted(user.getId(), now)) {
                return refuse(429, "rate_limited", false);
            }

            if (code == null) {
                return refuse(400, "unknown_code", true);
            }
            if (code.isDenied() || !code.isPending()) {
                return refuse(409, "code_not_pending", true);
            }
            if (code.isExpired()) {
                return refuse(410, "expired_code", true);
            }
            if (!CLIENT_ID.equals(code.getClientId())) {
                return refuse(403, "wrong_code_client", true);
            }
            String nonce = code.getNonce();
            if (nonce == null || !MessageDigest.isEqual(
                    nonce.getBytes(StandardCharsets.UTF_8), binding.getBytes(StandardCharsets.UTF_8))) {
                return refuse(403, "binding_mismatch", true);
            }

            return approveCode(code, approving, token);
        }

        private Response approveCode(OAuth2DeviceCodeModel code, UserSessionModel approving, AccessToken token) {
            ClientModel client = realm.getClientByClientId(code.getClientId());
            RootAuthenticationSessionModel root = session.authenticationSessions().createRootAuthenticationSession(realm);
            try {
                // What CibaGrantType.createUserSession does to sign somebody in without a browser.
                AuthenticationSessionModel authSession = root.createAuthenticationSession(client);
                authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
                authSession.setAction(AuthenticatedClientSessionModel.Action.AUTHENTICATE.name());
                authSession.setClientNote(OIDCLoginProtocol.ISSUER,
                        Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
                authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, code.getScope());
                authSession.setAuthenticatedUser(user);
                AuthenticationManager.setClientScopesInSession(session, authSession);

                ClientSessionContext context = AuthenticationProcessor.attachSession(
                        authSession, null, session, realm, connection, event.clone());
                UserSessionModel created = context.getClientSession().getUserSession();

                String authTime = approving.getNote(AuthenticationManager.AUTH_TIME);
                if (authTime == null && token.getAuth_time() != null) {
                    authTime = String.valueOf(token.getAuth_time());
                }
                if (authTime != null) {
                    created.setNote(AuthenticationManager.AUTH_TIME, authTime);
                }
                created.setNote(APPROVED_BY_NOTE, approving.getId());

                if (!DeviceGrantType.approveUserCode(session, realm, userCode, created.getId(), null)) {
                    session.sessions().removeUserSession(realm, created);
                    return refuse(410, "expired_code", true);
                }
                DeviceGrantType.removeDeviceByUserCode(session, realm, userCode);
                limits.recordApproval(user.getId(), now);

                event.session(created).detail("new_session", created.getId()).success();
                return cors.add(Response.noContent().header("Cache-Control", "no-store"));
            } finally {
                session.authenticationSessions().removeRootAuthenticationSession(realm, root);
            }
        }

        private Response refuse(int status, String error, boolean countsAsFailure) {
            if (ownsCode) {
                OAuth2DeviceCodeModel live = DeviceEndpoint.getDeviceByUserCode(session, realm, userCode);
                if (live != null && live.isPending() && !live.isDenied()) {
                    DeviceGrantType.denyUserCode(session, realm, userCode);
                }
            }
            if (countsAsFailure && user != null && limits.recordFailure(user.getId(), now)) {
                event.detail("blocked_for_seconds", String.valueOf(PairingLimits.BLOCK_SECONDS));
            }
            event.detail(Details.REASON, error).error(error);
            return cors.add(Response.status(status)
                    .type(MediaType.APPLICATION_JSON)
                    .header("Cache-Control", "no-store")
                    .entity(Map.of("error", error)));
        }

        private static String text(JsonNode json, String field, int maxLength) {
            JsonNode node = json == null ? null : json.get(field);
            if (node == null || !node.isTextual()) return null;
            String value = node.asText();
            return value.isEmpty() || value.length() > maxLength ? null : value;
        }
    }
}
