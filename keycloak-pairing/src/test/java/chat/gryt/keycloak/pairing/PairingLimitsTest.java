package chat.gryt.keycloak.pairing;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.SingleUseObjectProvider;

class PairingLimitsTest {

    // In memory; lifespans are ignored, so only PairingLimits' own windows expire anything.
    static final class MemoryStore implements SingleUseObjectProvider {
        final Map<String, Map<String, String>> entries = new HashMap<>();

        @Override public void put(String key, long lifespanSeconds, Map<String, String> notes) { entries.put(key, new HashMap<>(notes)); }
        @Override public Map<String, String> get(String key) { return entries.get(key); }
        @Override public Map<String, String> remove(String key) { return entries.remove(key); }
        @Override public boolean replace(String key, Map<String, String> notes) { return entries.replace(key, notes) != null; }
        @Override public boolean putIfAbsent(String key, long lifespanInSeconds) { return entries.putIfAbsent(key, new HashMap<>()) == null; }
        @Override public boolean contains(String key) { return entries.containsKey(key); }
        @Override public void close() { }
    }

    private final MemoryStore store = new MemoryStore();
    private final PairingLimits limits = new PairingLimits(store, "realm");

    @Test
    void aCodeGetsOneCall() {
        assertTrue(limits.claimCode("ABCDEFGH", 1000, 1300));
        assertFalse(limits.claimCode("ABCDEFGH", 1001, 1300));
        assertTrue(limits.claimCode("HGFEDCBA", 1001, 1300));
    }

    @Test
    void fiveApprovalsAnHour() {
        for (int i = 0; i < 4; i++) limits.recordApproval("u", 1000 + i);
        assertFalse(limits.approvalsExhausted("u", 1010));
        limits.recordApproval("u", 1005);
        assertTrue(limits.approvalsExhausted("u", 1010));
        assertFalse(limits.approvalsExhausted("other", 1010));
        // An hour on, the hourly count is clear again.
        assertFalse(limits.approvalsExhausted("u", 1000 + 3600 + 10));
    }

    @Test
    void twentyApprovalsADay() {
        int now = 100_000;
        for (int i = 0; i < 20; i++) {
            now += 3600 / 4;
            limits.recordApproval("u", now);
        }
        assertTrue(limits.approvalsExhausted("u", now + 3601));
        assertFalse(limits.approvalsExhausted("u", now + 86400));
    }

    @Test
    void tenFailuresBlockTheUser() {
        for (int i = 0; i < 9; i++) assertFalse(limits.recordFailure("u", 1000 + i));
        assertFalse(limits.isBlocked("u"));
        assertTrue(limits.recordFailure("u", 1009));
        assertTrue(limits.isBlocked("u"));
        assertFalse(limits.isBlocked("other"));
    }

    @Test
    void failuresOlderThanAnHourDropOut() {
        for (int i = 0; i < 9; i++) limits.recordFailure("u", 1000 + i);
        assertFalse(limits.recordFailure("u", 1000 + 3600 + 5));
        assertFalse(limits.isBlocked("u"));
    }
}
