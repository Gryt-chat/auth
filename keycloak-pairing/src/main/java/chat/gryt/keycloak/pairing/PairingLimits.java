package chat.gryt.keycloak.pairing;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.models.SingleUseObjectProvider;

/**
 * Rate limits kept in Keycloak's single-use object store, which expires entries by itself.
 * The store has no atomic increment, so two calls at the same instant can count as one.
 */
final class PairingLimits {

    static final int APPROVALS_PER_HOUR = 5;
    static final int APPROVALS_PER_DAY = 20;
    static final int FAILURES_PER_HOUR = 10;
    static final int BLOCK_SECONDS = 3600;

    private static final int HOUR = 3600;
    private static final int DAY = 86400;
    private static final String TIMES = "t";

    private final SingleUseObjectProvider store;
    private final String prefix;

    PairingLimits(SingleUseObjectProvider store, String realmId) {
        this.store = store;
        this.prefix = "gryt-pairing:" + realmId + ":";
    }

    // False when this user_code has had its one call already, whatever came of it.
    boolean claimCode(String userCode, int now, int codeExpiresAt) {
        long lifespan = Math.max(codeExpiresAt - now, 0) + 60L;
        return store.putIfAbsent(prefix + "code:" + userCode, lifespan);
    }

    boolean isBlocked(String userId) {
        return store.contains(prefix + "blocked:" + userId);
    }

    boolean approvalsExhausted(String userId, int now) {
        List<Integer> times = read(prefix + "approvals:" + userId, now, DAY);
        long lastHour = times.stream().filter(t -> t > now - HOUR).count();
        return lastHour >= APPROVALS_PER_HOUR || times.size() >= APPROVALS_PER_DAY;
    }

    void recordApproval(String userId, int now) {
        record(prefix + "approvals:" + userId, now, DAY);
    }

    // Returns true when this failure is the one that blocks the user.
    boolean recordFailure(String userId, int now) {
        int count = record(prefix + "failures:" + userId, now, HOUR);
        if (count < FAILURES_PER_HOUR) {
            return false;
        }
        store.put(prefix + "blocked:" + userId, BLOCK_SECONDS, new HashMap<>());
        return true;
    }

    private int record(String key, int now, int window) {
        List<Integer> times = read(key, now, window);
        times.add(now);
        StringBuilder joined = new StringBuilder();
        for (int t : times) {
            if (!joined.isEmpty()) joined.append(',');
            joined.append(t);
        }
        // put, not replace: replace takes no lifespan, so it can't renew the window.
        Map<String, String> notes = new HashMap<>();
        notes.put(TIMES, joined.toString());
        store.put(key, window, notes);
        return times.size();
    }

    private List<Integer> read(String key, int now, int window) {
        List<Integer> times = new ArrayList<>();
        Map<String, String> notes = store.get(key);
        String raw = notes == null ? null : notes.get(TIMES);
        if (raw == null || raw.isEmpty()) {
            return times;
        }
        for (String part : raw.split(",")) {
            try {
                int t = Integer.parseInt(part);
                if (t > now - window) times.add(t);
            } catch (NumberFormatException ignored) {
                // A mangled entry counts as nothing rather than failing the call.
            }
        }
        return times;
    }
}
