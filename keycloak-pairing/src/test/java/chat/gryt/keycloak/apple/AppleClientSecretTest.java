package chat.gryt.keycloak.apple;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class AppleClientSecretTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static KeyPair p256() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    private static String pem(KeyPair k) {
        String b = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(k.getPrivate().getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + b + "\n-----END PRIVATE KEY-----\n";
    }

    private static JsonNode part(String jwt, int i) throws Exception {
        return JSON.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[i]));
    }

    @Test
    void signsWhatAppleAsksFor() throws Exception {
        KeyPair k = p256();
        Instant now = Instant.ofEpochSecond(1_800_000_000L);
        String jwt = AppleClientSecret.mint(pem(k), "TEAM123456", "KEY1234567", "chat.gryt.signin", now);

        assertEquals("ES256", part(jwt, 0).get("alg").asText());
        assertEquals("KEY1234567", part(jwt, 0).get("kid").asText());
        JsonNode c = part(jwt, 1);
        assertEquals("TEAM123456", c.get("iss").asText());
        assertEquals("chat.gryt.signin", c.get("sub").asText());
        assertEquals("https://appleid.apple.com", c.get("aud").asText());
        assertEquals(1_800_000_000L, c.get("iat").asLong());
        assertTrue(c.get("exp").asLong() - c.get("iat").asLong() <= 15_777_000L, "Apple refuses more than six months");

        String[] p = jwt.split("\\.");
        Signature v = Signature.getInstance("SHA256withECDSAinP1363Format");
        v.initVerify(k.getPublic());
        v.update((p[0] + "." + p[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(v.verify(Base64.getUrlDecoder().decode(p[2])));
    }

    @Test
    void refusesValuesThatWouldBreakTheJson() throws Exception {
        String key = pem(p256());
        assertThrows(IllegalArgumentException.class, () -> AppleClientSecret.mint(key, "T\",\"x", "K", "c", Instant.now()));
        assertThrows(IllegalArgumentException.class, () -> AppleClientSecret.mint(key, "T", null, "c", Instant.now()));
        assertThrows(IllegalArgumentException.class, () -> AppleClientSecret.mint("", "T", "K", "c", Instant.now()));
    }
}
