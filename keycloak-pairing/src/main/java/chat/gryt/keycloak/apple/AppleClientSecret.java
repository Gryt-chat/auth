package chat.gryt.keycloak.apple;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.regex.Pattern;

/** Apple's client secret: a short-lived ES256 JWT signed with the team's Sign in with Apple key (.p8). */
final class AppleClientSecret {

    static final String AUDIENCE = "https://appleid.apple.com";
    static final long LIFETIME_SECONDS = 300;
    // These go into the JSON unescaped, so only the characters Apple uses for them get through.
    private static final Pattern SAFE = Pattern.compile("[A-Za-z0-9.\\-_]{1,128}");

    private AppleClientSecret() { }

    static String mint(String p8, String teamId, String keyId, String clientId, Instant now) {
        for (String v : new String[] { teamId, keyId, clientId }) {
            if (v == null || !SAFE.matcher(v).matches()) {
                throw new IllegalArgumentException("Apple team id, key id and client id must be set and plain");
            }
        }
        long iat = now.getEpochSecond();
        String header = "{\"alg\":\"ES256\",\"kid\":\"" + keyId + "\"}";
        String claims = "{\"iss\":\"" + teamId + "\",\"iat\":" + iat + ",\"exp\":" + (iat + LIFETIME_SECONDS)
                + ",\"aud\":\"" + AUDIENCE + "\",\"sub\":\"" + clientId + "\"}";
        String input = b64(header.getBytes(StandardCharsets.UTF_8)) + "." + b64(claims.getBytes(StandardCharsets.UTF_8));
        try {
            // P1363 gives the raw r||s that JWS wants, not DER.
            Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
            sig.initSign(privateKey(p8));
            sig.update(input.getBytes(StandardCharsets.US_ASCII));
            return input + "." + b64(sig.sign());
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("could not sign the Apple client secret", e);
        }
    }

    static PrivateKey privateKey(String p8) throws Exception {
        if (p8 == null || p8.isBlank()) throw new IllegalArgumentException("the Apple .p8 key is not set");
        String body = p8.replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
    }

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
